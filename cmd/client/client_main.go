package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"loophid/backend_service"
	"loophid/pkg/client"
	http_server "loophid/pkg/http/server"
	"strings"
	"time"
)

var listenString = flag.String("p", "80", "HTTP server port(s) to listen on. Comma seperated, prefix with ssl: for SSL enabled ports.")
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

	var allListenAddresses []string
	if strings.Contains(*listenString, ",") {
		allListenAddresses = strings.Split(*listenString, ",")
	} else {
		allListenAddresses = append(allListenAddresses, *listenString)
	}

	var sslListenAddresses []string
	var httpListenAddresses []string
	for _, p := range allListenAddresses {
		if strings.HasPrefix(p, "ssl:") {
			cp, _ := strings.CutPrefix(p, "ssl:")
			sslListenAddresses = append(sslListenAddresses, cp)
		} else {
			httpListenAddresses = append(httpListenAddresses, p)
		}
	}

	// Start the plain HTTP servers.
	for _, listenAddr := range httpListenAddresses {
		go func(port string) {
			s := http_server.NewHttpServer(c, port, *myPublicIP)
			fmt.Printf("Starting server on : %s\n", port)
			log.Fatal(s.Start())
		}(listenAddr)
	}

	// Start the SSL HTTP servers.
	for _, listenAddr := range sslListenAddresses {
		go func(port string) {
			s := http_server.NewSSLHttpServer(c, port, *sslCert, *sslKey, *myPublicIP)
			fmt.Printf("Starting SSL server on : %s\n", port)
			log.Fatal(s.Start())
		}(listenAddr)
	}

	// Setup the go routing for regularly reporting the status back to the
	// backend.
	statusChan := make(chan bool)
	ticker := time.NewTicker(time.Minute * 5)
	sReq := backend_service.StatusRequest{
		Ip: *myPublicIP,
		//ListenPort:    ports,
		//ListenPortSsl: sslPorts,
	}

	go func() {
		for {
			select {
			case <-statusChan:
				ticker.Stop()
				slog.Info("Status channel stopped")
				return
			case <-ticker.C:
				if _, err := c.SendStatus(&sReq); err != nil {
					slog.Warn("error sending status", slog.String("error", err.Error()))
				}
			}
		}
	}()

	<-finish
	statusChan <- true
}
