package main

import (
	"flag"
	"log"
	"loophid/pkg/client"
	http_server "loophid/pkg/http/server"
	"strconv"
	"strings"
)

var listenPort = flag.String("p", "80", "HTTP server port(s) to listen on. Comma seperated")
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

	finish := make(chan bool)
	var ports []int
	if strings.Contains(*listenPort, ",") {
		for _, p := range strings.Split(*listenPort, ",") {
			intVal, _ := strconv.Atoi(p)
			ports = append(ports, intVal)
		}
	} else {
		intVal, _ := strconv.Atoi(*listenPort)
		ports = append(ports, intVal)
	}

	for _, port := range ports {
		go func(port int) {
			var s *http_server.HttpServer
			if *sslCert != "" && *sslKey != "" {
				log.Printf("Starting HTTPS server (%d)", port)
				s = http_server.NewSSLHttpServer(c, int64(port), *sslCert, *sslKey, *myPublicIP)
			} else {
				log.Printf("Starting HTTP server (%d)", port)
				s = http_server.NewHttpServer(c, int64(port), *myPublicIP)
			}

			log.Fatal(s.Start())
		}(port)
	}

	<-finish
}
