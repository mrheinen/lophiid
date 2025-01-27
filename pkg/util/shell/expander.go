package shell

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

type Expander struct {
	compiledVarRegex *regexp.Regexp
	varMap           map[string]string
}

func NewExpander() *Expander {
	compiledRegex, err := regexp.Compile(`([A-Za-z0-9_\-]+)=(.*)`)
	if err != nil {
		slog.Error("failed to compile regex", slog.String("error", err.Error()))
		return nil
	}

	return &Expander{
		compiledVarRegex: compiledRegex,
		varMap:           make(map[string]string),
	}
}

func CleanupVariableValue(vari string) string {

	vari = strings.TrimSpace(vari)
	if vari[0] == '\'' || vari[0] == '"' {
		if len(vari) >= 4 {
			vari = vari[1 : len(vari)-1]
		}
	}

	return vari
}

func (n Expander) ExpandChunk(chunk string) string {

	// Try to resolve variables. This does not take quoting into account yet.
	if strings.Contains(chunk, "$") {
		for vName, vValue := range n.varMap {
			chunk = strings.ReplaceAll(chunk, "$"+vName, vValue)
			chunk = strings.ReplaceAll(chunk, "${"+vName+"}", vValue)
		}
	}

	// Try to find variable definitions.
	match := n.compiledVarRegex.FindStringSubmatch(chunk)
	if len(match) == 3 {
		fmt.Println(match[1], match[2])
		n.varMap[match[1]] = CleanupVariableValue(match[2])
	}

	return chunk
}

func (n *Expander) Expand(reader Iterator) []string {
	outputBuffer := []string{}

	for {
		chunk, hasMore := reader.Next()
		chunk = strings.TrimSpace(chunk)

		chunk = n.ExpandChunk(chunk)

		// Handle for loops
		if strings.HasPrefix(chunk, "for") {
			// for VARIABLE in 1 2 3 4 5
			parts := strings.SplitN(chunk, " ", 4)
			variableName := parts[1]
			variableValues := CleanupVariableValue(parts[3])

			for {

				var nextChunk string
				nextChunk, hasMore = reader.Next()
				if nextChunk == "done" || !hasMore {
					break
				}

				if nextChunk == "do" {
					continue
				}

				for _, val := range strings.Split(variableValues, " ") {
					n.varMap[variableName] = val

					updatedChunk := n.ExpandChunk(nextChunk)
					outputBuffer = append(outputBuffer, updatedChunk)
				}
			}

			// Continue here because everything gets already added to the output
			// buffer in the loop above
			if !hasMore {
				break
			} else {
				continue
			}
		}

		if chunk != "" {
			outputBuffer = append(outputBuffer, chunk)
		}

		if !hasMore {
			break
		}
	}

	return outputBuffer
}
