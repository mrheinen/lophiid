package shell

// Command and possible outputs that can be found in shell scripts.
var commandOutputs = map[string][]string{
	"uname -mp": {"x86_64 x86_64", "arm64 arm", "aarch64 unknown", "armv7l unknown"},
	"uname -m":  {"x86_64", "arm64", "aarch64", "armv7l"},
	"uname -i":  {"x86_64", "arm64", "aarch64", "armv7l"},
}
