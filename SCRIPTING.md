# Scripted responses

## Introduction
In the content page, you can have static responses and scripted responses.
Scripted responses are javascript based and are run by the backend each time a
request matches a rule linked to the scripted response.

The script will get access to the request and response object. Additionally
there are some build in methods exposed to the script (and please open a bug if
there are some others you want to see exposed as well)

## Overview of the script

Each script needs to have at least the __validate method and the
createResponse method.

### The __validate() method

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

### the createResponse() method

This method should contain the logic to analyze the "request" object and then to
set the values of th "response" object. You can for example set header values or
set the response body.

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
methods are exposed.

## Response object

