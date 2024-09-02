# Scripted responses

## Introduction
In the content page, you can have static responses and scripted responses.
Scripted responses are javascript based and are run by the backend each time a
request matches a rule linked to the scripted response.

The script will get access to the request and response object. Additionally
there are some build in methods exposed to the script (and please open a bug if
there are some others you want to see exposed as well)

The build in methods allow you to encode/decode content, query the database and
even run commands. This document describes what methods are exposed to the
script.  It is highly recommended to also peak at the code in ./pkg/javascript
for more background on how things are implemented.

## Overview of the script

Each script needs to have at least the __validate method and the
createResponse method.

### The __validate() method - REQUIRED

This is a test method that is called whenever you make changes to the script.
Whenever the method returns something different than an empty string, the caller
will assume that validation failed.

In most cases you want use the script something like this:

 * First populate the "request" object with test data
 * Now call createResponse and check it's return value to see if there were any
   errors.
 * Now analyse the "response" object and check what values the createResponse
   method has modified/set.
 * Return "" on success or a string indicating the error whever an error
   happens.

### the createResponse() method - REQUIRED

This method should contain the logic to analyze the "request" object and then to
set the values of the "response" object. You can for example set header values or
set the response body.

Upon success this method needs to return an empty string. Upon error it should
return a string that describes the error.

If this method is successful; the resulting response body will be stored in the
database and visible when viewing requests that matched a rule with this script.
This helps to check if the scripts are working and especially with highly
dynamic responses reated by scripts it is useful to be able to verify real world
invocations.

### Example script

```shell
function __validate() {
  // Set request URI to what we want to match on.
  request.uri = "/?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=sch9bgwq"

  // Call createResponse. We expect it to extract the string sch9bgwq, to
  // calculate it's md5 value and to set this as the response.
  const ret = createResponse();
  if (ret != "") {
    return "create response returned " + ret;
  }

  if (response.bodyString() != "17c356f80abc6b0b355dd3c9e06dbcc5") {
    return "unexpected response: " + response.bodyString();
  }
  return "";
}

function createResponse() {
  // Extract the string from the URI.
  const uriRegex = /md5&vars\[1\]\[\]=([a-zA-Z0-9]+)/;
  const res = request.uri.match(uriRegex);

  if (!res || res.length != 2) {
    return "uri regex did not match";
  }

  // Use the build in md5sum method to make the hash.
  let ret = util.crypto.md5sum(res[1]);
  response.setBody(ret);
  return "";
}

```


# Exposed objects & methods

In general, whenever a struct from golang is exposed via Javascript you need to
take into account that:

* All exposed attributes are lower case. This means request.SourceIP becomes
request.sourceip.
* All exposed methods start with lower case. This means that request.ModelID()
  in golang becomes request.modelID() in javascript.

## Request object

Look at the Request object in database/database.go to see what attributes and
methods are exposed. Examples are:

 * request.id - the ID of the request
 * request.uri - the uri of the request
 * request.raw - the raw request

## Response object

Similar to request, it's easier to look at the Response struct in
pkg/database/database.go to see what kind of attributes are available.

In addition the following methods are added in the Javascript layer (and so not
visible in the Response struct):

 * SetBody(string) - This will set the respose body to the given value.
 * GetBody() - This will return the body as a string.

These two are necessary because the body is stored in []bytes which is hard to
handle in Javascript.

## General methods

### util.encoding.base64.encode(string)

Base64 encodes the given string and returns the encoded string.

### util.encoding.base64.decode(string)

Returns the base64 decoded value of the given string. On error an empty string
is returned.

### util.crypto.md5sum(string)

Returns an md5 hash of the given string.

### util.crypto.sha256sum(string)

Returns a sha256 hash of the given string.

### util.crypto.sha1sum(string)

Returns a sha1 hash of the given string.

### util.time.sleep(int)

Sleep the given amount of milliseconds.

## Cache

The cache deserves a little bit extra documentation. The purpose of the cache is
to allow information to be shared between scripts that anwer multiple requests
for the same session.

For example:

 * Request 1 sends a POST and wants to put a random string in a file. The script
   responding will use the cache to store this random script.
 * With request 2 the attacker tries to fetch the file with the random string.
   The script for this request will be able to get the random string from the
   cache and sends this to the attacker.

At the moment the cache timeout is 30 minutes and the timeout is refresh
whenever a value is written to the same key.  Read access to a cache entry does
not modify the timeout.

A cache is only shared between scripts run for the same honeypot/source IP
pairs.

### util.cache.set(key string, value string)

Update the cache with the given key string value.

### util.cache.get(key string)

Get the value for "key" from the cache. Returns an empty string if there is no
value.

## Database

### util.database.getContentById(id int64)

Tries to fetch database.Content with ID `id` from the database. Returns null
upon error so please check for that. The returned object is a ContentWrapper
type and get methods like getID(), getData() and getContentType() to get these
fields from the embedded database.Content.

## Command execution

Running commands is not allowed by default and commands need to be explicitly
allowed from the backend config. Arguments given to commands are not controlled
and therefore you need to be careful that your command cannot be abused via
parameters you give it. Especially when using information from the attackers
request as a parameter to the command.

Example scenario: an attacker sends a payload that spawns a dropbear SSH daemon
on a random (to us, not the attacker) port. The attacker then tries to connect
to that port on the honeypot.  You could use the command execution functionality
to create a script that gets the port of the dropbear daemon and the IP of the
honeypot that received the requests as parameters. The script will spawn an SSH
honeypot and will forward that given port from the honeypot IP to this SSH
honeypot.

Commands executed should exit immediately and not cause delays.  Any large
processing should be wrapped in a shell script that forks things to the background.

> [!IMPORTANT]
> These commands run on the backend server and not on the honeypot.

### util.runner.getCommandRunner()

Get the command runner which is a class that is intended to be single use for
running a single command.

### <command runner>.runCommand(cmd, arg1, arg2, ...) bool

Run a single command, returns true or false depending on success. For example:

```shell
var r = util.runner.getCommandRunner();
if (!r.runCommand("/bin/echo", "aaa")) {
    return 'command not allowed?';
}
```

It's important that the command itself is allowlisted in the backend
config. Additionally the command should exit immediately which means that if you
want to run a command for a long time (like in the background) then you need to
wrap it in a shell script (or have the command fork to the background itself).

After running the command you can use r.getStdout() and r.getStderr() to get
relevant output of the command. This is especially useful for error handling.

### <command runner>.getStdout() string

Get the stdout output of the command.

### <command runner>.getStderr() string

Get the stderr output of the command.
