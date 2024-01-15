package main

import (
	"flag"
	"fmt"
	"loophid/pkg/vt"
)

var apikey = flag.String("vt-key", "", "VirusTotal API key")
var url = flag.String("url", "", "The url to scan")
var anID = flag.String("id", "", "The ID to fetch metadata for")

func main() {

	flag.Parse()
	vtc := vt.NewVTClient(*apikey)

	if *url != "" {
		id, err := vtc.SendURL(*url)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		fmt.Printf("ID: %s\n", id)
	}

	if *anID != "" {
		data, err := vtc.GetAnalysis(*anID)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		fmt.Printf("data: %s\n", data)
	}
}
