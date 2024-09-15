// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
package agent

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"lophiid/backend_service"
	"lophiid/pkg/backend"
	"lophiid/pkg/util"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"
)

type HttpServer struct {
	mux        *http.ServeMux
	client     backend.BackendClient
	ssl        bool
	sslCert    string
	sslKey     string
	listenAddr string
	port       int64
	publicIP   string
	ipCache    *util.StringMapCache[bool]
}

// NewHttpServer creates a new initialized HttpServer struct.
func NewHttpServer(c backend.BackendClient, listenAddr string, publicIP string) *HttpServer {
	_, portString, err := net.SplitHostPort(listenAddr)
	if err != nil {
		slog.Warn("could not parse listen address", slog.String("address", listenAddr), slog.String("error", err.Error()))
		return nil
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		slog.Warn("could not parse port", slog.String("address", listenAddr), slog.String("port", portString), slog.String("error", err.Error()))
		return nil
	}

	return &HttpServer{
		client:     c,
		ssl:        false,
		listenAddr: listenAddr,
		publicIP:   publicIP,
		port:       int64(port),
		ipCache:    nil,
	}
}

func NewSSLHttpServer(c backend.BackendClient, listenAddr string, sslCert string, sslKey string, publicIP string) *HttpServer {
	_, portString, err := net.SplitHostPort(listenAddr)
	if err != nil {
		slog.Warn("could not parse listen address", slog.String("address", listenAddr), slog.String("error", err.Error()))
		return nil
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		slog.Warn("could not parse port", slog.String("address", listenAddr), slog.String("port", portString), slog.String("error", err.Error()))
		return nil
	}

	return &HttpServer{
		client:     c,
		ssl:        true,
		sslCert:    sslCert,
		sslKey:     sslKey,
		listenAddr: listenAddr,
		publicIP:   publicIP,
		port:       int64(port),
		ipCache:    nil,
	}
}

func (h *HttpServer) Start() error {
	return h.StartWithIPCache(nil)
}

// Start starts the HTTP server with an IP cache.
// The IP cache will be used to collect all IPs that have been seen.
func (h *HttpServer) StartWithIPCache(ipCache *util.StringMapCache[bool]) error {
	h.mux = http.NewServeMux()
	h.mux.HandleFunc("/", h.catchAll)
	h.ipCache = ipCache

	if h.ssl {
		return http.ListenAndServeTLS(h.listenAddr, h.sslCert, h.sslKey, h.mux)
	}
	return http.ListenAndServe(h.listenAddr, h.mux)

}

// catchAll receives all HTTP requests.  It parses the requests and sends them
// to the backend using grpc. The backend will the tell catchAll how to respond.
func (h *HttpServer) catchAll(w http.ResponseWriter, r *http.Request) {

	// Keep track of what IPs have connected.
	if h.ipCache != nil {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			slog.Error("error parsing remote address", slog.String("address", r.RemoteAddr), slog.String("error", err.Error()))
		} else {
			h.ipCache.Store(ip, false)
		}
	}

	raw, err := httputil.DumpRequest(r, true)
	if err != nil {
		slog.Error("Problem decoding requests", slog.String("error", err.Error()), slog.String("request", fmt.Sprintf("%+#v", r)))
	}

	pr := &backend_service.HandleProbeRequest{
		RequestUri: r.RequestURI,
		Request: &backend_service.HttpRequest{
			TimeReceived:  time.Now().Unix(),
			Raw:           string(raw),
			Method:        r.Method,
			Proto:         r.Proto,
			ContentLength: r.ContentLength,
			RemoteAddress: r.RemoteAddr,
			HoneypotIp:    h.publicIP,

			ParsedUrl: &backend_service.ParsedURL{
				Scheme:   r.URL.Scheme,
				User:     r.URL.User.Username(),
				Host:     r.URL.Host,
				Port:     h.port,
				Path:     r.URL.Path,
				RawPath:  r.URL.RawPath,
				RawQuery: r.URL.RawQuery,
				Fragment: r.URL.Fragment,
			},
		},
	}

	// Important to keep in mind that a parameter might be repeated with the same name but a different value.
	for k, v := range r.URL.Query() {
		pr.Request.ParsedUrl.Query = append(pr.Request.ParsedUrl.Query,
			&backend_service.KeyValues{
				Key:   k,
				Value: v,
			})
	}
	// Passwords are optional.
	pass, isSet := r.URL.User.Password()
	if isSet {
		pr.Request.ParsedUrl.Password = pass
	}

	for k, v := range r.Header {
		pr.Request.Header = append(pr.Request.Header, &backend_service.KeyValue{
			Key:   k,
			Value: v[0], // TODO: Check this
		})
	}

	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error("unable to parse body", slog.String("error", err.Error()))
		} else {
			pr.Request.Body = b
		}
	}

	// TODO: process and return response from the server.
	res, err := h.client.HandleProbeRequest(pr)
	if err != nil {
		log.Printf("unable to process request: %s", err)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html></html>"))
		return
	}

	slog.Debug("got new request", slog.String("request_uri", pr.RequestUri))

	if res == nil || res.Response == nil {
		slog.Error("got nil!!", slog.String("response", fmt.Sprintf("%+v", res)), slog.String("probe_request", fmt.Sprintf("%+v", pr)))
		return
	}

	// At least one header is always set.
	for _, h := range res.Response.Header {
		w.Header().Set(h.Key, h.Value)
	}

	switch res.Response.StatusCode {
	case "200":
		w.WriteHeader(http.StatusOK)
	case "301":
		w.WriteHeader(http.StatusMovedPermanently)
	case "302":
		w.WriteHeader(http.StatusTemporaryRedirect)
	case "400":
		w.WriteHeader(http.StatusBadRequest)
	case "401":
		w.WriteHeader(http.StatusUnauthorized)
	case "403":
		w.WriteHeader(http.StatusForbidden)
	case "404":
		w.WriteHeader(http.StatusNotFound)
	case "500":
		w.WriteHeader(http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusOK)
	}

	w.Write(res.GetResponse().Body)
}
