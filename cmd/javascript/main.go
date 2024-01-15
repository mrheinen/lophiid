package main

import (
	"flag"
	"fmt"
	"loophid/pkg/database"
	"loophid/pkg/javascript"
)

var script = flag.String("s", "", "The script to run")
var validate = flag.Bool("validate", false, "Whether to validate the script (requires __validate)")

func main() {

	flag.Parse()
	js := javascript.NewGojaJavascriptRunner()

	req := database.Request{
		ID:   42,
		Uri:  "this is uri",
		Body: []byte("this is patrick"),
	}
	//script := "function returnResponse(uri, body) { return uri; }"
	out, err := js.RunScript(*script, req, *validate)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return
	}

	fmt.Printf("OUTPUT: %s\n", out)

}
