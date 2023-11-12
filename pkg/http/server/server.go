package http_server

import (
	// Note: Also remove the 'os' import.

	"fmt"
	"greyhole/backend_service"
	"greyhole/pkg/client"
	"io"
	"log"
	"net/http"
)

type HttpServer struct {
	mux     *http.ServeMux
	client  client.BackendClient
	sslCert string
	sslKey  string
}

func NewHttpServer(c client.BackendClient, sslCert string, sslKey string) *HttpServer {
	return &HttpServer{
		client: c,
		sslCert: sslCert,
		sslKey: sslKey,
	}
}

func (h *HttpServer) Start(listen_string string) error {
	h.mux = http.NewServeMux()
	h.mux.HandleFunc("/", h.catchAll)
	return http.ListenAndServeTLS(listen_string, h.sslCert, h.sslKey, h.mux)
}

func (h *HttpServer) catchAll(w http.ResponseWriter, r *http.Request) {
	pr := &backend_service.HandleProbeRequest{
		RequestUri: r.RequestURI,
		Request: &backend_service.HttpRequest{
			Method:        r.Method,
			Proto:         r.Proto,
			ContentLength: r.ContentLength,
			RemoteAddress: r.RemoteAddr,
			ParsedUrl: &backend_service.ParsedURL{
				Scheme:   r.URL.Scheme,
				User:     r.URL.User.Username(),
				Host:     r.URL.Host,
				Port:     r.URL.Port(),
				Path:     r.URL.Path,
				RawPath:  r.URL.RawPath,
				RawQuery: r.URL.RawQuery,
				Fragment: r.URL.Fragment,
			},
		},
	}

	// Important to keep in mind that a parameter might be repeated with the same
	// name but a different value.
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
		pr.Request.Header = append(pr.Request.Header, &backend_service.KeyValues{
			Key:   k,
			Value: v,
		})
	}

	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("parsing body: %s", err)
		} else {
			pr.Request.Body = string(b)
		}
	}

	h.client.HandleProbeRequest(pr)

	fmt.Printf("got / request\n")
	io.WriteString(w, "Hi!\n")
}
