# AI Integration

## Introduction
Lophiid can work with a local LLM, such as served with llama.cpp or ollama,
or OpenAI directly. The LLM is used for assisting in response creation to certain
attacks and additionally is used to triage incoming requests.

### AI assisted triage

#### Description

AI assisted triage is currently limited to the following:
For each request a unique CmpHash hash is created that uses all request fields except
for the Host: header and some commonly changed parameters such as "user" and
"password".  This hash is intended to be the same for the same request across
multiple hosts and the excluded parameters are specifically for keeping
bruteforce noise down.

For every unique CmpHash, and this means each unique request, the backend
will use the AI to:

- Describe the request
- Determine whether the request is malicious
- Determine the application that was likely targeted by the request
- Determine the possible CVE that was targeted
- Determine the Common Weakness (CWE) that was exploited

This information is surfaced in the UI. Additionally for every malicious event
that was for a request that has no rule associated with it the AI will create an
IP event that can be viewed and queried in the Events tab in the UI.  This helps
to highlight potentially interesting requests.

#### Enabling
Configure the backend with the parameters of the AI. This is documented in the
[example config](./backend-config.yaml) in the AI section. In the config set
"enable_describer" to true or 1.
Make sure the (local) LLM is running and that the lophiid backend was restarted with the new config.

### AI assisted responses

#### Description

Say you emulate an application that is vulnerable to remote command
injection and you want to get as much interaction with attackers are possible.
If an attacker send a payload of "echo <random string>; uname" and thus expects
the random string and OS to be returned in the response then there are
currently two options to deal with this in lophiid:

 * You create a content script that parses the random string from the attack and
   echos it back.
 * You use an LLM to parse the request and tell lophiid what to reply.

In the case of the content script you will have better performance than the LLM
but there is one problem. The scripted parsing will limit the different kind of
payloads that you can handle and will get quite complex when you want to support
more kind of payloads (e.g. echo <random string>; id; uname -a).

This is where the LLM integration shines. It will interpret the commands and
will give example outputs that will then be embedded in the response.

> [!IMPORTANT]
> Lophiid and the LLM will NOT execute the commands. The LLM will merely return
> example outputs of the given commands.

As a sidenote though, it is possible to combine content scripts with LLM
integration but that is currently beyond the scope of this document.

#### Enabling

To enable AI support for a content rule you need to do the following:

 * Configure the backend with the parameters of the AI. This is documented in
   the [example config](./backend-config.yaml). Make sure the local LLM is
   running and that the lophiid backend was restarted with the new config.
 * Select a "responder" in the Responder field of the rule. You need to select a
   responder that matches with the type of vulnerability being exploited.
 * Write a regular expression that is used against the Raw field of the request
   and that extracts a string that is given to the responser.
 * Optional: select a response decoder. This will decode the string you selected
   with the regex before it is given to the decoder. Useful if, for example, the
   string is uri encoded.
 * Optional: in the Content for the rule, add the following string to
   the Data field somewhere: %%%LOPHIID_PAYLOAD_RESPONSE%%% . In the response to
   the attacker this string will be substituted with the AI reply. If you do not
   add this string then the AI reply is appended to the response.

> [!NOTE]
> The Raw field of the request contains the raw request with all headers. You
> can see this in the "HTTP Request" field in the Requests tab of the UI.

#### The concept of responders

Responders can be seen as AI interfaces that are specific for a vulnerability or
exploitation technique. They contain an AI prompt that prepares the AI for how
it should interpret the data the rule is sending (remember, what you grabbed
with the regex) and tells the AI how it should respond.

#### SOURCE_CODE_INJECTION responder

To use this responder you will use the regex to grep the source code that is
being send by the attacker to the server. The responder will try to determine
what the output is that this source code would generate. Currently only tested
with simple PHP snippets.

#### CODE_EXECUTION responder

To use this render you let the regex grab the commands that the attacker is
trying to execute on the honeypot. The responder will try to determine what the
output of those commands would be and returns that.

#### AUTO responder

This responder will use AI to extract the payload itself from the request. You
therefore do not need to specify a regex.

#### Some implementation details

The AI interaction caused by a rule is cached and the timeout of this cache is
configurable. The cache will make sure that we do not do multiple lookups if the
extracted string (from the Raw field) is the same as a previous one. This will
help to make lophiid snappy when it comes to response times and additionally
keep the system load low.

If the AI is not responding in time or if there is in fact no AI configured then
lophiid will fallback to sending the reply without the additional AI input.

The implementation was tested with Gemma 2 27b running with llama.cpp. You can
use different models but if you do then try out how things work with the LLM CLI
util that is located at ./cmd/llm . With this utility you can test out different
responders with your user provided strings to review the LLM output.
