package main

import (
	"flag"
	"log"
	"loophid/pkg/client"
	http_server "loophid/pkg/http/server"
)

var listenPort = flag.Int64("p", 443, "HTTP server port to listen on")
var serverLocation = flag.String("s", "localhost:41110", "RPC server location")
var sslCert = flag.String("c", "", "SSL certificate file")
var sslKey = flag.String("k", "", "SSL certificate key")

// Used for reporting
var myPublicIP = flag.String("i", "", "My public IP address")

func main() {

	flag.Parse()

	if *myPublicIP == "" {
		log.Fatal("Provide the public IP address with -i ")
	}
	c := client.InsecureBackendClient{}
	if err := c.Connect(*serverLocation); err != nil {
		log.Fatalf("%s", err)
	}
	defer c.Disconnect()

	var s *http_server.HttpServer
	if *sslCert != "" && *sslKey != "" {
		log.Printf("Starting HTTPS server (%d)", *listenPort)
		s = http_server.NewSSLHttpServer(&c, *listenPort, *sslCert, *sslKey, *myPublicIP)
	} else {
		log.Printf("Starting HTTP server (%d)", *listenPort)
		s = http_server.NewHttpServer(&c, *listenPort, *myPublicIP)
	}

	log.Fatal(s.Start())
}
