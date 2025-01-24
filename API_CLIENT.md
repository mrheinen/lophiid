# This page describes the CLI API client CLI tool

## Description
The API client is a handy command line tool that allows you to interact with the
API server. It currently is especially useful for creating new Apps in lophiid
and adding Content and Rules to it.

The tool can be pointed to a URL (or a file with URLs) and it will fetch
the content and stores it in a new Content entry in lophiid. While doing
so it also prefers important headers such as Server and Last-Modified
which may require specific values for some attackers to consider the
target real.

A typical scenario for using this tool is when you found an interesting target
on the Internet (e.g. via shodan) and want to copy the content from that target
into lophiid.

## How to run / build

Build the API client using the following command:
```shell
bazel build //cmd/api_client:api-client
```

Throughout this document we will use ```bazel run``` to run the tool so you do
not necessarily need to build it up front when using the examples from here.

### Adding an application

When adding a new application you will need to at least specify the app name,
version and vendor. Additionally you always need to specify the location of the
API server with -api-server.

Here is an example for adding an app:

```shell
$ bazel run //cmd/api_client:api_client -- \
   -api-server http://127.0.0.1:8088 \  # This is the location of the API server
   -api-key ca357d9a-b98f-429c-83d7-e8088f69ba2f \ # This is the API key
   -app-name Big-IP \
   -app-vendor F5 \
   -app-version unknown

INFO: Analyzed target //cmd/api_client:api_client (0 packages loaded, 0 targets configured).
INFO: Found 1 target...
Target //cmd/api_client:api_client up-to-date:
  bazel-bin/cmd/api_client/api_client_/api_client
INFO: Elapsed time: 0.095s, Critical Path: 0.00s
INFO: 1 process: 1 internal.
INFO: Build completed successfully, 1 total action
INFO: Running command line: bazel-bin/cmd/api_client/api_client_/api_client -api-server http://127.0.0.1:8088 -api-key ca357d9a-b98f-429c-83d7-e8088f69ba2f -app-name Big-IP -app-vendor F5 -app-version unknown
Created app with ID: 101
```

Take a note of the ID (101 in this case) as you will need it to add Content to
the app. If you want you can now also open the UI and go to the Apps tab and
check that this app was created.
### Importing previously exported Apps

Apps can be exported and also can be found in the ./rules folder of the GitHub
repository. These apps can be imported via the web UI (one by one) and via the
CLI (one by one or a whole directory).

To import a single app with the CLI, use the following example:

```shell

$ bazel run //cmd/api_client:api_client -- \
  -api-server http://127.0.0.1:8088 \
  -api-key ca357d9a-b98f-429c-83d7-e8088f69ba2f \
  -app-import \
  -app-import-file ./rules/Spring\ Framework-5.2.20.yaml
...
time=2024-09-13T11:51:56.090-04:00 level=INFO msg="Imported app" app="rules/Spring Framework-5.2.20.yaml"

```

To import a directory recursively use the following example:


```shell

$ bazel run //cmd/api_client:api_client -- \
  -api-server http://127.0.0.1:8088 \
  -api-key ca357d9a-b98f-429c-83d7-e8088f69ba2f \
  -app-import \
  -app-import-dir ./rules/
...
time=2024-09-13T11:51:56.090-04:00 level=INFO msg="Imported app" app="rules/Spring Framework-5.2.20.yaml"
time=2024-09-13T11:51:56.090-05:00 level=INFO msg="Imported app" app="rules/Spring Framework-5.2.21.yaml"
time=2024-09-13T11:51:56.090-06:00 level=INFO msg="Imported app" app="rules/Bla DieBla-42.yaml"
...

```

### Adding Content and a Rule to an app using a single URL

An application needs Rules to match requests and it needs Contents for the rules
to serve when a request matches. You can do this for a single URL by using the
-url and -app-id flags.

Here is an example:

```shell
$ bazel run //cmd/api_client:api_client -- \
  -api-server http://127.0.0.1:8088 \
  -api-key ca357d9a-b98f-429c-83d7-e8088f69ba2f \
  -app-id 101 \    # The App ID for which to create the rules
  -url https://xx.84.27.70:8443/tmui/login.jsp # The URL which should be fetched.
INFO: Analyzed target //cmd/api_client:api_client (0 packages loaded, 0 targets configured).
INFO: Found 1 target...
Target //cmd/api_client:api_client up-to-date:
  bazel-bin/cmd/api_client/api_client_/api_client
INFO: Elapsed time: 0.098s, Critical Path: 0.00s
INFO: 1 process: 1 internal.
INFO: Build completed successfully, 1 total action
INFO: Running command line: bazel-bin/cmd/api_client/api_client_/api_client -api-server http://127.0.0.1:8088 -api-key ca357d9a-b98f-429c-83d7-e8088f69ba2f -app-id 101 -url https://xx.84.27.70:8443/tmui/login.jsp
time=2024-06-30T15:34:01.507-04:00 level=DEBUG msg="Fetching URL" url="http://127.0.0.1:8088/app/segment?q=id%3A101&offset=0&limit=10"
time=2024-06-30T15:34:01.508-04:00 level=INFO msg="fetching url" url=https://xx.84.27.70:8443/tmui/login.jsp
time=2024-06-30T15:34:02.322-04:00 level=INFO msg="added content and rule" content_id=246 rule_id=240 port=0
```

Note that in the last line port=0 means that the rule that was created will
match on any port. Also in the last line as the rule and content IDs which
allows you to do to the Rule or Content tab in the web UI to see what was
created (and make any modifications if necessary).

[!CAUTION]
Always check the Content's that were created to see if there aren't any links/references to the original URL from which you fetched it. Also update cookies and CSRF tokens with random generated strings as defined in [TEMPLATING](./TEMPLATING.md)


#### Validating the results

In the UI, under the Content you will now be able to see the added entry:
![The added Content entry](https://github.com/mrheinen/lophiid/blob/main/images/content-show-cli-result.png?raw=true)

Click in the UI "Extra options" to also see what headers will be set with the content. These values were fetched from the source.

Next look under the Rules tab look at the added rule:
![The added rule](https://github.com/mrheinen/lophiid/blob/main/images/rule-added-via-cli.png?raw=true)

### Adding multiple URLs from a file

This is the same as above but using a file with URLs. Instead of using the -url
flag you will now use the -url-file flag and give the location of the file with
URLs as it's value.

In the URL file you want one URL on every line.
