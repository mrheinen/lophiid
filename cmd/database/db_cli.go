package main

import (
	"flag"
	"fmt"
	"loophid/pkg/database"
	"os"
)

var contentAdd = flag.Bool("content-add", false, "Add content")
var contentFile = flag.String("content-file", "", "Content file to read data from")
var contentName = flag.String("content-name", "", "Name of the content")
var contentType = flag.String("content-type", "text/plain", "Content-type header value")
var contentServer = flag.String("content-server", "Apache", "Content server header")
var contentList = flag.Bool("content-list", false, "List all content")
var contentDel = flag.Bool("content-del", false, "Delete content with the ID given with --id")
var databaseID = flag.Int64("id", 0, "Database ID to be used with other operations")

var ruleAdd = flag.Bool("rule-add", false, "Add content rule")
var rulePath = flag.String("rule-path", "", "Path of the rule")
var rulePathMatch = flag.String("rule-path-matching", "exact", "How to match the path against the request: 'exact' (default), 'prefix', 'suffix', 'contains', 'regex'")
var ruleMethod = flag.String("rule-method", "ANY", "HTTP method to match on ('GET', 'POST', ..)")
var ruleBody = flag.String("rule-body", "", "Content to find in the body of the request")
var ruleBodyMatch = flag.String("rule-body-matching", "exact", "How to match the body string against the request: 'exact' (default), 'prefix', 'suffix', 'contains', 'regex'")

func main() {

	flag.Parse()
	dbc := database.PostgresClient{}
	err := dbc.Init("postgres://lo:test@localhost/lophiid")
	if err != nil {
		fmt.Printf("Error opening database: %s", err)
		return
	}

	defer dbc.Close()

	if *ruleAdd {
		if *rulePath == "" || *databaseID == 0 {
			fmt.Println("Please also use --rule-path <path> and --id <content id>")
			return
		}

		// TODO: more sanity checks here.
		lid, err := dbc.InsertContentRule(*databaseID, *rulePath, *rulePathMatch, *ruleMethod, *ruleBody, *ruleBodyMatch)
		if err != nil {
			fmt.Printf("Unable to add content rule: %s\n", err)
			return
		}
		fmt.Printf("Added new content rule (ID: %d)\n", lid)
	}

	if *contentAdd {
		if *contentFile == "" || *contentName == "" {
			fmt.Println("Please specify a file with --content-file and name with --content-name")
			return
		}

		dat, err := os.ReadFile(*contentFile)
		if err != nil {
			fmt.Printf("Problem reading file %s: %s\n", *contentFile, err)
			return
		}

		id, err := dbc.InsertContent(*contentName, string(dat), *contentType, *contentServer)
		if err != nil {
			fmt.Printf("inserting content to database: %s", err)
			return
		}

		fmt.Printf("Inserted content. New ID is: %d", id)
	}

	if *contentDel {
		if *databaseID == 0 {
			fmt.Println("Please specify an ID with --id <id> ")
			return
		}

		dbc.DeleteContent(*databaseID)
	}

	if *contentList {
		cts, err := dbc.GetContent()
		if err != nil {
			fmt.Printf("getting content: %s\n", err)
		}

		for _, ct := range cts {
			fmt.Printf("%d %s %s %50s\n", ct.ID, ct.Name, ct.ContentType, ct.Content)
		}
	}

}
