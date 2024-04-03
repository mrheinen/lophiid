package http_server

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"loophid/backend_service"
	"loophid/pkg/client"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"
)

type HttpServer struct {
	mux        *http.ServeMux
	client     client.BackendClient
	ssl        bool
	sslCert    string
	sslKey     string
	listenAddr string
	port       int64
	publicIP   string
}

// NewHttpServer creates a new initialized HttpServer struct.
func NewHttpServer(c client.BackendClient, listenAddr string, publicIP string) *HttpServer {
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
	}
}

func NewSSLHttpServer(c client.BackendClient, listenAddr string, sslCert string, sslKey string, publicIP string) *HttpServer {
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
	}
}

// Start starts the HTTP server.
func (h *HttpServer) Start() error {
	h.mux = http.NewServeMux()
	h.mux.HandleFunc("/", h.catchAll)

	if h.ssl {
		return http.ListenAndServeTLS(h.listenAddr, h.sslCert, h.sslKey, h.mux)
	}
	return http.ListenAndServe(h.listenAddr, h.mux)

}

// catchAll receives all HTTP requests.  It parses the requests and sends them
// to the backend using grpc. The backend will the tell catchAll how to respond.
func (h *HttpServer) catchAll(w http.ResponseWriter, r *http.Request) {
	raw, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Printf("Problem decoding requests: %s", err)
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
			log.Printf("parsing body: %s", err)
		} else {
			pr.Request.Body = b
		}
	}

	// TODO: process and return response from the server.
	res, err := h.client.HandleProbeRequest(pr)
	if err != nil {
		log.Printf("unable to process request: %s", err)
	}

	fmt.Printf("got request for: %s\n", pr.RequestUri)

	if res == nil || res.Response == nil {
		fmt.Printf("Got nil ? Res: %+v, ProbeRequest: %+v\n", res, pr)
		fmt.Printf("HTTP request: %+v\n", r)
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
