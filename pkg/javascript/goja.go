package javascript

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"loophid/backend_service"
	"loophid/pkg/database"
	"loophid/pkg/util"
	"time"

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

// Contains helper methods to decode strings.
type Encoding struct {
	Base64 Base64 `json:"base64"`
}

type Base64 struct {
}

// util.encoding.base64.decode()
func (d Base64) Decode(s string) string {
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		slog.Warn("unable to decode string", slog.String("input", s), slog.String("error", err.Error()))
		return ""
	}
	return string(dec)
}

// util.encoding.base64.encode()
func (d Base64) Encode(s string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(s))
}

type Time struct {
}

// Sleep allows a program to sleep the specified duration in milliseconds.
func (t Time) Sleep(msec int) {
	time.Sleep(time.Duration(msec) * time.Millisecond)
}

// Contains helper structs for use inside javascript. The following methods are
// available:
//
// util.crypto.md5sum("string") returns an md5 checksum of the given string.
type Util struct {
	Crypto   Crypto       `json:"crypto"`
	Time     Time         `json:"time"`
	Cache    CacheWrapper `json:"cache"`
	Encoding Encoding     `json:"encoding"`
}

type JavascriptRunner interface {
	RunScript(script string, req database.Request, res *backend_service.HttpResponse, validate bool) error
}

type GojaJavascriptRunner struct {
	strCache *util.StringMapCache[string]
	metrics  *GojaMetrics
}

func NewGojaJavascriptRunner(metrics *GojaMetrics) *GojaJavascriptRunner {
	// The string cache timeout should be a low and targetted
	// for the use case of holding something in cache between
	// a couple requests for the same source.
	cache := util.NewStringMapCache[string](time.Minute * 30)
	cache.Start()
	return &GojaJavascriptRunner{
		strCache: cache,
		metrics:  metrics,
	}
}

type CacheWrapper struct {
	keyPrefix string
	strCache  *util.StringMapCache[string]
}

func (c *CacheWrapper) Set(key string, value string) {
	fkey := fmt.Sprintf("%s-%s", c.keyPrefix, key)
	c.strCache.Store(fkey, value)
}

func (c *CacheWrapper) Get(key string) string {
	fkey := fmt.Sprintf("%s-%s", c.keyPrefix, key)
	val, err := c.strCache.Get(fkey)
	if err != nil {
		return ""
	}
	return *val
}

// ResponseWrapper wraps the response and makes it available via methods in the
// javascript context.
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

	startTime := time.Now()

	vm := goja.New()
	// Map all fields with json tags to these tags in javascript. The second
	// argument "true" will cause the method names to start with a lower case
	// character.
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	vm.Set("util", Util{
		Crypto: Crypto{},
		Time:   Time{},
		Cache: CacheWrapper{
			keyPrefix: fmt.Sprintf("%s%s", req.SourceIP, req.HoneypotIP),
			strCache:  j.strCache,
		},
		Encoding: Encoding{},
	})

	vm.Set("request", req)
	vm.Set("response", ResponseWrapper{response: res})

	_, err := vm.RunString(script)
	if err != nil {
		j.metrics.javascriptSuccessCount.WithLabelValues(RunFailed).Add(1)
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
		j.metrics.javascriptSuccessCount.WithLabelValues(RunFailed).Add(1)
		return fmt.Errorf("couldn't find method createResponse")
	}
	err = vm.ExportTo(ref, &createResponse)
	if err != nil {
		return fmt.Errorf("couldn't export method: %s", err)
	}

	scriptOutput := createResponse()

	if scriptOutput != "" {
		j.metrics.javascriptSuccessCount.WithLabelValues(RunFailed).Add(1)
		return fmt.Errorf("%w: %s", ErrScriptComplained, scriptOutput)
	}
	j.metrics.javascriptSuccessCount.WithLabelValues(RunSuccess).Add(1)
	j.metrics.javascriptSuccessExecutionTime.Observe(time.Since(startTime).Seconds())

	return nil
}

type FakeJavascriptRunner struct {
	StringToReturn string
	ErrorToReturn  error
}

func (f *FakeJavascriptRunner) RunScript(script string, req database.Request, res *backend_service.HttpResponse, validate bool) error {
	return f.ErrorToReturn
}
