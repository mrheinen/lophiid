package http_server

import (
	// Note: Also remove the 'os' import.

	"fmt"
	"greyhole/backend_service"
	"greyhole/pkg/client"
	"io"
	"net/http"
)

type HttpServer struct {
	mux    *http.ServeMux
	client client.BackendClient
}

func NewHttpServer(c client.BackendClient) *HttpServer {
	return &HttpServer{
		client: c,
	}
}

func (h *HttpServer) Start(listen_string string) error {
	h.mux = http.NewServeMux()
	h.mux.HandleFunc("/", h.catchAll)
	return http.ListenAndServe(listen_string, h.mux)
}

func (h *HttpServer) catchAll(w http.ResponseWriter, r *http.Request) {

	pr := &backend_service.HandleProbeRequest{
		Method:     r.Method,
		RequestUri: r.RequestURI,
	}

	h.client.HandleProbeRequest(pr)

	fmt.Printf("got / request\n")
	io.WriteString(w, "This is my website!\n")
}
