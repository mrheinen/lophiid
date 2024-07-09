package main

import (
	"log/slog"
	"loophid/pkg/database"
	"loophid/pkg/util"
	"os"
)

var docHeader = `

# Search keywords

This document is automatically generated from the structs in database.go
an describes all the different keywords that can be searched per model /
page in the UI.

Note that in the UI, on pages where search is available, the same
information can be found by clicking on ? icon in the left corner of
the search bar.

`

func main() {

	fo, err := os.Create("SEARCH_KEYWORDS.md")
	if err != nil {
		slog.Error("Unable to create file", slog.String("error", err.Error()))
		return
	}
	fo.WriteString(docHeader)
	WriteModelToFile(fo, database.Request{}, "Requests")
	WriteModelToFile(fo, database.Content{}, "Content")
	WriteModelToFile(fo, database.ContentRule{}, "Rules")
	WriteModelToFile(fo, database.Application{}, "Apps")
	WriteModelToFile(fo, database.Download{}, "Downloads")
	WriteModelToFile(fo, database.Honeypot{}, "Honeypots")
	WriteModelToFile(fo, database.StoredQuery{}, "Manage Queries")
	WriteModelToFile(fo, database.Tag{}, "Manage tags")
	defer fo.Close()

}

func WriteModelToFile(fo *os.File, model interface{}, pageName string) {

	keyMap := database.GetDatamodelDocumentationMap(model)
	modelName := util.GetStructName(model)
	fo.WriteString("## Keywords for the " + pageName + " (model: " + modelName + ")\n\n")

	fo.WriteString("|Keyword|Type|Description|\n")
	fo.WriteString("|___|___|___|\n")
	for key, fde := range keyMap {
		fo.WriteString("|" + key + "|" + fde.FieldType + "|" + fde.FieldDoc + "|\n")
	}
	fo.WriteString("\n\n")

}
