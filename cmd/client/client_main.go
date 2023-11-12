package main

import (
	"flag"
	"greyhole/pkg/client"
	http_server "greyhole/pkg/http/server"
	"log"
)

var listenString = flag.String("l", ":443", "HTTP server listen string (e.g. \":443\")")
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

	log.Printf("%s %s\n", *sslCert, *sslKey)
	s := http_server.NewHttpServer(&c, *sslCert, *sslKey)
	log.Fatal(s.Start(*listenString))
}
