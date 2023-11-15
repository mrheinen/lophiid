package main

import (
	"flag"
	"fmt"
	"greyhole/pkg/database"
	"os"
)

var contentAdd = flag.Bool("content-add", false, "Add content")
var contentFile = flag.String("content-file", "", "Content file to read data from")
var contentName = flag.String("content-name", "", "Name of the content")
var contentList = flag.Bool("content-list", false, "List all content")
var contentDel = flag.Bool("content-del", false, "Delete content with the ID given with --id")
var databaseID = flag.Int64("id", 0, "Database ID to be used with other operations")

func main() {

	flag.Parse()
	dbc := database.DatabaseClient{}
	err := dbc.Init("postgres://lo:test@localhost/lophiid")
	if err != nil {
		fmt.Printf("opening database: %s", err)
		return
	}

	defer dbc.Close()

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

		id, err := dbc.InsertContent(*contentName, string(dat))
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
			fmt.Printf("%d %s %50s\n", ct.ID, ct.Name, ct.Content)
		}
	}

}
