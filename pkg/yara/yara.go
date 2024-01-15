package yara

import (
	"fmt"
	"os/exec"
)

type YaraRunner struct {
	yaraBinFile   string
	yaraRulesFile string
}

func NewYaraRunner(binFile string, rulesFile string) *YaraRunner {
	return &YaraRunner{
		yaraBinFile:   binFile,
		yaraRulesFile: rulesFile,
	}
}

func (y *YaraRunner) RunOnFile(file string) error {
	out, err := exec.Command(y.yaraBinFile, y.yaraRulesFile, file).Output()
	if err != nil {
		return fmt.Errorf("when running agains %s : %s", file, err)
	}

	fmt.Printf("OUTPUT: %s", out)
	return nil
}
