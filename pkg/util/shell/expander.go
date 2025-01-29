package shell

import (
	"fmt"
	"log/slog"
	"math/rand"
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

// CleanupVariableValue removes quotes from a variable value.
func CleanupVariableValue(vari string) string {
	vari = strings.TrimSpace(vari)

	if len(vari) < 2 {
		return vari
	}

	lastChar := vari[len(vari)-1]
	if (vari[0] == '\'' && lastChar == '\'') || (vari[0] == '"' && lastChar == '"') {
		if len(vari) >= 4 {
			vari = vari[1 : len(vari)-1]
		}
	}

	return vari
}

// getCommandOutput returns the output of a shell command if is defined in the
// commandOutputs map.
func getCommandOutput(value string) (string, error) {
	if len(value) < 4 {
		return "", fmt.Errorf("value too short: %s", value)
	}

	command := value[2 : len(value)-1]

	res, ok := commandOutputs[command]
	if !ok {
		return "", fmt.Errorf("unknown command: %s", command)
	}

	if len(res) == 1 {
		return res[0], nil
	}

	// Return a random example.
	randomIndex := rand.Intn(len(res))
	return res[randomIndex], nil
}

// ExpandChunk receives a shell command chunk and expands variables. It also
// registers new variables which are then used in future expansions.
// Returns the expanded string.
func (n *Expander) ExpandChunk(chunk string) string {
	if n == nil || n.compiledVarRegex == nil {
		return chunk
	}

	// Try to resolve variables. This does not take quoting into account yet.
	if strings.Contains(chunk, "$") {
		for vName, vValue := range n.varMap {
			chunk = strings.ReplaceAll(chunk, "$"+vName, vValue)
			chunk = strings.ReplaceAll(chunk, "${"+vName+"}", vValue)
		}
	}

	// Try to find variable definitions.
	match := n.compiledVarRegex.FindStringSubmatch(chunk)
	if len(match) >= 3 {
		if strings.HasPrefix(match[2], "$(") {
			output, err := getCommandOutput(match[2])
			if err != nil {
				n.varMap[match[1]] = CleanupVariableValue(match[2])
			} else {
				n.varMap[match[1]] = output
			}
		} else {
			n.varMap[match[1]] = CleanupVariableValue(match[2])
		}
	}

	return chunk
}

// Expand reads a shell script chunk by chunk and expands variables.
func (n *Expander) Expand(reader Iterator) []string {
	if n == nil || reader == nil {
		return nil
	}

	outputBuffer := []string{}

	for {
		chunk, hasMore := reader.Next()
		chunk = strings.TrimSpace(chunk)

		chunk = n.ExpandChunk(chunk)

		// Handle for loops
		if strings.HasPrefix(chunk, "for") {
			parts := strings.SplitN(chunk, " ", 4)
			if len(parts) < 4 {
				slog.Error("invalid for loop syntax", slog.String("chunk", chunk))
				if !hasMore {
					break
				}
				continue
			}

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
