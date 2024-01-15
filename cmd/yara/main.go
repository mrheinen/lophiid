package main

import (
	"flag"
	"fmt"
	"loophid/pkg/yara"
)

var yaraBin = flag.String("bin", "", "The yara binary location")
var yaraRules = flag.String("rules", "", "The yara rules")
var file = flag.String("file", "", "The file to scan")

func main() {

	flag.Parse()
	yr := yara.NewYaraRunner(*yaraBin, *yaraRules)
	if err := yr.RunOnFile(*file); err != nil {
		fmt.Printf("%s\n", err)
	}

}
