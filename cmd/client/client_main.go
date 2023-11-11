package main

import (
	"flag"
	"greyhole/pkg/client"
	http_server "greyhole/pkg/http/server"
	"log"
)

var listenString = flag.String("l", ":8888", "HTTP server listen string (e.g. \":80\")")
var serverLocation = flag.String("s", "localhost:41110", "RPC server location")

func main() {

	c := client.InsecureBackendClient{}
	if err := c.Connect(*serverLocation); err != nil {
		log.Fatalf("%s", err)
	}
	defer c.Disconnect()

	s := http_server.NewHttpServer(&c)
	s.Start(*listenString)
}
