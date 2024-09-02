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
package javascript

import (
	"errors"
	"fmt"
	"lophiid/backend_service"
	"lophiid/pkg/database"
	"lophiid/pkg/util"
	"time"

	"github.com/dop251/goja"
)

var ErrScriptComplained = errors.New("script complained")

// Contains helper structs for use inside javascript.
type Util struct {
	Crypto   Crypto                `json:"crypto"`
	Time     Time                  `json:"time"`
	Cache    CacheWrapper          `json:"cache"`
	Encoding Encoding              `json:"encoding"`
	Database DatabaseClientWrapper `json:"database"`
	Runner   CommandRunnerWrapper  `json:"runner"`
}

type JavascriptRunner interface {
	RunScript(script string, req database.Request, res *backend_service.HttpResponse, validate bool) error
}

type GojaJavascriptRunner struct {
	strCache        *util.StringMapCache[string]
	dbClient        database.DatabaseClient
	allowedCommands []string
	commandTimeout  time.Duration
	metrics         *GojaMetrics
}

func NewGojaJavascriptRunner(dbClient database.DatabaseClient, allowedCommands []string, commandTimeout time.Duration, metrics *GojaMetrics) *GojaJavascriptRunner {
	// The string cache timeout should be a low and targetted
	// for the use case of holding something in cache between
	// a couple requests for the same source.
	cache := util.NewStringMapCache[string]("goja_cache", time.Minute*30)
	cache.Start()
	return &GojaJavascriptRunner{
		strCache:        cache,
		metrics:         metrics,
		dbClient:        dbClient,
		allowedCommands: allowedCommands,
		commandTimeout:  commandTimeout,
	}
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
		Database: DatabaseClientWrapper{
			dbClient: j.dbClient,
		},
		Encoding: Encoding{},
		Runner: CommandRunnerWrapper{
			allowedCommands: j.allowedCommands,
			commandTimeout:  j.commandTimeout,
		},
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
