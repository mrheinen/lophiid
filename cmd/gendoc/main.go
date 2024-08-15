// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
package main

import (
	"log/slog"
	"lophiid/pkg/database"
	"lophiid/pkg/util"
	"os"
	"sort"
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

	fo.WriteString("| Keyword | Type | Description |\n")
	fo.WriteString("| --- | --- | --- |\n")

	// Create a slice to hold the keys
	keys := make([]string, 0, len(keyMap))
	for key := range keyMap {
		keys = append(keys, key)
	}

	// Sort the keys
	sort.Strings(keys)

	// Iterate over the sorted keys
	for _, key := range keys {
		fde := keyMap[key]
		fo.WriteString("| " + key + " | " + fde.FieldType + " | " + fde.FieldDoc + " |\n")
	}

	fo.WriteString("\n\n")
}
