package javascript

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"loophid/backend_service"
	"loophid/pkg/database"

	"github.com/dop251/goja"
)

var ErrScriptComplained = errors.New("script complained")

// Contains helper methods for crypto operations.
type Crypto struct {
}

// Md5sum returns an md5 checksum of the given string.
func (c Crypto) Md5sum(s string) string {
	h := md5.New()
	io.WriteString(h, s)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Contains helper structs for use inside javascript. The following methods are
// available:
//
// util.crypto.md5sum("string") returns an md5 checksum of the given string.
type Util struct {
	Crypto Crypto `json:"crypto"`
}

type JavascriptRunner interface {
	RunScript(script string, req database.Request, res *backend_service.HttpResponse, validate bool) error
}

type GojaJavascriptRunner struct {
	util Util
}

func NewGojaJavascriptRunner() *GojaJavascriptRunner {
	return &GojaJavascriptRunner{
		util: Util{
			Crypto: Crypto{},
		},
	}
}

type ResponseWrapper struct {
	response *backend_service.HttpResponse
}

func (r *ResponseWrapper) AddHeader(key string, value string) {
	r.response.Header = append(r.response.Header, &backend_service.KeyValue{
		Key:   key,
		Value: value,
	})
}

func (r *ResponseWrapper) SetBody(body string) {
	r.response.Body = []byte(body)
}

func (r *ResponseWrapper) BodyString() string {
	return string(r.response.Body)
}

// The JavascriptRunner will run the given script and makes the given request
// available as 'request' inside the javascript context.
func (j *GojaJavascriptRunner) RunScript(script string, req database.Request, res *backend_service.HttpResponse, validate bool) error {
	vm := goja.New()
	// Map all fields with json tags to these tags in javascript. The second
	// argument "true" will cause the method names to start with a lower case
	// character.
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))

	vm.Set("request", req)
	vm.Set("response", ResponseWrapper{response: res})
	vm.Set("util", j.util)

	_, err := vm.RunString(script)
	if err != nil {
		return fmt.Errorf("couldnt run script: %s", err)
	}

	// Validation requires a method called __validate to be present in the script.
	// The javascript method itself is supposed to have all logic to test the
	// createResponse method. Here we only care about calling it and making sure
	// that there is no output (output means error).
	if validate {
		var validateScript func() string
		ref := vm.Get("__validate")
		if ref == nil {
			return fmt.Errorf("couldn't find method __validate")
		}
		err = vm.ExportTo(ref, &validateScript)
		if err != nil {
			return fmt.Errorf("couldn't export method: %s", err)
		}

		if out := validateScript(); out != "" {
			return fmt.Errorf("validation failed: %s", out)
		}
	}

	var createResponse func() string
	ref := vm.Get("createResponse")
	if ref == nil {
		return fmt.Errorf("couldn't find method createResponse")
	}
	err = vm.ExportTo(ref, &createResponse)
	if err != nil {
		return fmt.Errorf("couldn't export method: %s", err)
	}

	scriptOutput := createResponse()

	if scriptOutput != "" {
		return fmt.Errorf("%w: %s", ErrScriptComplained, scriptOutput)
	}

	return nil
}

type FakeJavascriptRunner struct {
	StringToReturn string
	ErrorToReturn  error
}

func (f *FakeJavascriptRunner) RunScript(script string, req database.Request, res *backend_service.HttpResponse, validate bool) (string, error) {
	return f.StringToReturn, f.ErrorToReturn
}
