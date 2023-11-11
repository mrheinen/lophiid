package main

import (
	"flag"
	"fmt"
	"greyhole/pkg/backend"
)

var serverLocation = flag.String("s", "localhost:41110", "RPC server listen string")

func main() {

	b := backend.BackendServer{}
	if err := b.Start(*serverLocation); err != nil {
		fmt.Printf("%s", err)

	}
}
