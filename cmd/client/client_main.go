package main

import (
	"flag"
	"log"
	"loophid/pkg/client"
	http_server "loophid/pkg/http/server"
	"strings"
)

var listenPort = flag.Int64("p", 443, "HTTP server port to listen on")
var serverLocation = flag.String("s", "localhost:41110", "RPC server location")
var sslCert = flag.String("c", "", "HTTP SSL certificate file")
var sslKey = flag.String("k", "", "HTTP SSL certificate key")
var caCert = flag.String("ssl-cacert", "", "gRPC CA certificate")
var clientCert = flag.String("ssl-client-cert", "", "gRPC client certificate")
var clientKey = flag.String("ssl-client-key", "", "gRPC client key")

// Used for reporting
var myPublicIP = flag.String("i", "", "My public IP address")

func main() {

	flag.Parse()

	if *myPublicIP == "" {
		log.Fatal("Provide the public IP address with -i ")
	}

	var c client.BackendClient
	if *caCert != "" && *clientCert != "" && *clientKey != "" {
		sParts := strings.Split(*serverLocation, ":")
		log.Printf("Creating secure backend client. Server: %s", sParts[0])
		c = &client.SecureBackendClient{
			CACert:     *caCert,
			ClientCert: *clientCert,
			ClientKey:  *clientKey,
			ServerFQDN: sParts[0],
		}
		if err := c.Connect(*serverLocation); err != nil {
			log.Fatalf("%s", err)
		}
	} else {
		c = &client.InsecureBackendClient{}
		if err := c.Connect(*serverLocation); err != nil {
			log.Fatalf("%s", err)
		}
	}

	defer c.Disconnect()
	var s *http_server.HttpServer
	if *sslCert != "" && *sslKey != "" {
		log.Printf("Starting HTTPS server (%d)", *listenPort)
		s = http_server.NewSSLHttpServer(c, *listenPort, *sslCert, *sslKey, *myPublicIP)
	} else {
		log.Printf("Starting HTTP server (%d)", *listenPort)
		s = http_server.NewHttpServer(c, *listenPort, *myPublicIP)
	}

	log.Fatal(s.Start())
}
