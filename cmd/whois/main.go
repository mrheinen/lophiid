package main

import (
	"flag"
	"fmt"
	"github.com/likexian/whois"
)

var ip = flag.String("ip", "", "The IP to check")

func main() {

	flag.Parse()
	result, err := whois.Whois(*ip)
	if err == nil {
		fmt.Println(result)
	}

}
