package main

import (
	"flag"
	"fmt"
	"loophid/pkg/vt"
	"time"
)

var apikey = flag.String("apikey", "", "VirusTotal API key")
var ip = flag.String("ip", "", "The IP to check")

func main() {

	flag.Parse()
	vtc := vt.NewVTClient(*apikey, time.Hour * 24)
	ret, err := vtc.CheckIP(*ip)
	if err != nil {
		fmt.Printf("Got error: %s\n", err)
		return
	}

	fmt.Printf("%+v\n", ret)
}
