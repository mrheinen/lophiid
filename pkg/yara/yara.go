package yara

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	yarax "github.com/VirusTotal/yara-x/go"
)

const YaraExtension = ".yar"

type Yara interface {
	LoadRulesFromDirectory(dir string) error
	ScanDirectoryRecursive(dir string, callback func(string, []YaraResult)) error
	ScanFile(file string) ([]YaraResult, error)
}

type YaraxWrapper struct {
	compiler *yarax.Compiler
	rules    *yarax.Rules
	scanner  *yarax.Scanner
}

type YaraResultMetadata struct {
	Identifier string
	Value      interface{}
}

type YaraResult struct {
	Identifier string
	Metadata   []YaraResultMetadata
	Tags       []string
}

func (y *YaraxWrapper) Init() error {
	compiler, err := yarax.NewCompiler()
	if err != nil {
		return fmt.Errorf("error creating compiler: %w", err)
	}

	y.compiler = compiler
	return nil
}

var metadataStrings = map[string]bool{
	"author":             true,
	"reference":          true,
	"description":        true,
	"malpedia_reference": true,
	"malpedia_version":   true,
	"malpedia_license":   true,
	"malpedia_sharing":   true,
}

func PrintYaraResult(file string, results []YaraResult) {
	fmt.Printf("File: %s\n", file)

	for _, res := range results {
		fmt.Printf("  Identifier: %s\n", res.Identifier)
		for _, m := range res.Metadata {
			_, ok := metadataStrings[strings.ToLower(m.Identifier)]
			if ok {
				fmt.Printf("  %s: %s\n", m.Identifier, m.Value)
			}
		}

		if len(res.Tags) > 0 {
			fmt.Printf("  Tags: %s\n", strings.Join(res.Tags, ","))
		}
	}
}

func (y *YaraxWrapper) LoadRulesFromDirectory(dir string) error {
	if y.compiler == nil {
		return fmt.Errorf("compiler not initialized")
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if strings.HasSuffix(path, YaraExtension) {
			buf, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("error reading file: %w", err)
			}

			slog.Debug("loading rule", slog.String("path", path))
			err = y.compiler.AddSource(string(buf), yarax.WithOrigin(path))
			if err != nil {
				slog.Error("error adding rule to compiler", slog.String("path", path), slog.String("err", err.Error()))
				return nil
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error loading yara rules: %w", err)
	}

	return nil
}

// ScanDirectoryRecursive scan the directory with the Yara rules.
func (y *YaraxWrapper) ScanDirectoryRecursive(dir string, callback func(string, []YaraResult)) error {
	if y.compiler == nil {
		return fmt.Errorf("compiler not initialized")
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {

		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		fileResults, err := y.ScanFile(path)
		if err != nil {
			return err
		}

		if len(fileResults) > 0 {
			callback(path, fileResults)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error loading yara rules: %w", err)
	}

	return nil
}

func (y *YaraxWrapper) ScanFile(file string) ([]YaraResult, error) {
	ret := []YaraResult{}

	slog.Info("scanning file", slog.String("file", file))
	if y.compiler == nil {
		return ret, fmt.Errorf("compiler not initialized")
	}

	if y.rules == nil {
		y.rules = y.compiler.Build()
		slog.Info("Yara rules compiled", slog.Int("count", y.rules.Count()))
	}

	if y.scanner == nil {
		y.scanner = yarax.NewScanner(y.rules)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return ret, fmt.Errorf("error reading file: %w", err)
	}

	results, err := y.scanner.Scan(data)
	if err != nil {
		return ret, fmt.Errorf("error scanning file: %w", err)
	}

	// Iterate over the matching rules.
	for _, r := range results.MatchingRules() {
		tRes := YaraResult{}
		tRes.Identifier = r.Identifier()
		tRes.Tags = append(tRes.Tags, r.Tags()...)

		for _, md := range r.Metadata() {
			tRes.Metadata = append(tRes.Metadata, YaraResultMetadata{
				Identifier: md.Identifier(),
				Value:      md.Value(),
			})
		}

		ret = append(ret, tRes)
	}

	return ret, nil
}
