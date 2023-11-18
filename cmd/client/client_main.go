package main

import (
	"flag"
	"loophid/pkg/client"
	http_server "loophid/pkg/http/server"
	"log"
)

var listenPort = flag.Int64("p", 443, "HTTP server port to listen on")
var serverLocation = flag.String("s", "localhost:41110", "RPC server location")
var sslCert = flag.String("c", "", "SSL certificate file")
var sslKey = flag.String("k", "", "SSL certificate key")

func main() {

	flag.Parse()
	c := client.InsecureBackendClient{}
	if err := c.Connect(*serverLocation); err != nil {
		log.Fatalf("%s", err)
	}
	defer c.Disconnect()

	var s *http_server.HttpServer
	if *sslCert != "" && *sslKey != "" {
		log.Printf("Starting HTTPS server (%d)", *listenPort)
		s = http_server.NewSSLHttpServer(&c, *listenPort, *sslCert, *sslKey)
	} else {
		log.Printf("Starting HTTP server (%d)", *listenPort)
		s = http_server.NewHttpServer(&c, *listenPort)
	}

	log.Fatal(s.Start())
}
