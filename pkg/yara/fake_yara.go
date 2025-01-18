package yara

type FakeYara struct {
	ErrorToReturn       error
	YaraResultsToReturn []YaraResult
}

func (f *FakeYara) LoadRulesFromDirectory(dir string) error {
	return f.ErrorToReturn
}

func (f *FakeYara) ScanDirectoryRecursive(dir string, callback func(string, []YaraResult)) error {
	return f.ErrorToReturn
}

func (f *FakeYara) ScanFile(file string) ([]YaraResult, error) {
	return f.YaraResultsToReturn, f.ErrorToReturn
}
