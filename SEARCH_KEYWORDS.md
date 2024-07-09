

# Search keywords

This document is automatically generated from the structs in database.go
an describes all the different keywords that can be searched per model /
page in the UI.

Note that in the UI, on pages where search is available, the same
information can be found by clicking on ? icon in the left corner of
the search bar.

## Keywords for the Requests (model: Request)

| Keyword | Type | Description |
| --- | --- | --- |
| content_type | string | The Content-Type header value |
| content_length | int64 | The Content-Length header value |
| method | string | The HTTP method (e.g. GET, POST, PUT, DELETE, ...) |
| source_ip | string | The HTTP client source IP |
| content_id | int64 | The Content ID that was served |
| time_received | Time | The date and time the honeypot received the request |
| content_dynamic | bool | A bool indicating if the Content is dynamic (script based) |
| uri | string | The request URI |
| body |  | The request body |
| source_port | int64 | The HTTP client source port |
| raw | string | The raw HTTP request |
| path | string | The URL path |
| query | string | The query section of the URL |
| raw_response | string | The raw HTTP response (only used for scripted Content) |
| rule_id | int64 | The ID of the rule that matched this request |
| starred | bool | A bool if the request is starred |
| id | int64 | The ID of the request |
| proto | string | The HTTP protocol (e.g. HTTP/1.0) |
| host | string | The HTTP Host header value |
| honeypot_ip | string | The honeypot IP that received the request |
| base_hash | string | A base hash to find similar requests |
| port | int64 | The HTTP server port |
| referer | string | The referer header value |
| headers | FlatArray[string] | The client HTTP headers |
| updated_at | Time | The date and time of the last update |
| user_agent | string | The User-Agent value |
| created_at | Time | The date and time of creation |


## Keywords for the Content (model: Content)

| Keyword | Type | Description |
| --- | --- | --- |
| id | int64 | The ID of the content |
| data |  | The content data itself |
| description | string | The content description |
| server | string | The HTTP server with which the content is served |
| updated_at | Time | time.Time of last update |
| created_at | Time | time.Time of creation |
| name | string | The content name |
| content_type | string | The HTTP content-type |
| status_code | string | The HTTP status code |
| script | string | The content script |
| headers | FlatArray[string] | The content HTTP headers |


## Keywords for the Rules (model: ContentRule)

| Keyword | Type | Description |
| --- | --- | --- |
| body | string | The body matching string |
| method | string | The HTTP method the rule matches on |
| port | int64 | The TCP port the rue matches on. |
| uri_matching | string | The URI matching method (exact, regex, ..) |
| body_matching | string | The body matching method |
| created_at | Time | Creation date of the rule |
| updated_at | Time | Last update date of the rule |
| id | int64 | The rule ID |
| alert | bool | A bool (0 or 1) indicating if the rule should alert |
| content_id | int64 | The ID of the Content this rule serves |
| app_id | int64 | The ID of the application for which this rule is |
| uri | string | The URI matching string |


## Keywords for the Apps (model: Application)

| Keyword | Type | Description |
| --- | --- | --- |
| os | string | The OS on which the application runs |
| link | string | A reference link |
| created_at | Time | Date and time of creation |
| updated_at | Time | Date and time of last update |
| id | int64 | The ID of the application |
| name | string | The application name |
| version | string | The application version |
| vendor | string | The application vendor |


## Keywords for the Downloads (model: Download)

| Keyword | Type | Description |
| --- | --- | --- |
| vt_url_analysis_id | string | The virus total URL analysis ID |
| vt_analysis_suspicious | int64 | Virus total results marked suspicious |
| port | int64 | Server port |
| used_url | string | Actually used download URL |
| ip | string | Download server IP |
| sha256sum | string | SHA256 sum of the download |
| times_seen | int64 | How often this was seen |
| vt_file_analysis_id | string | The virus total file analysis ID |
| vt_analysis_harmless | int64 | Virus total results marked harmless |
| id | int64 | The ID of the download |
| created_at | Time | Date and time of creation |
| content_type | string | The content type (mime) of the download (reported by server) |
| original_url | string | Original download URL |
| honeypot_ip | string | Honeypot IP used for download |
| request_id | int64 | ID of the request where the download originated from |
| detected_content_type | string | The content type (mime) as detected |
| host | string | The Host header value used in downloading |
| file_location | string | The file location of the download |
| last_request_id | int64 | The request ID of the last request with this download |
| size | int64 | Size in bytes of the download |
| last_seen_at | Time | Date and time of last update |
| raw_http_response | string | The HTTP response of the download server |
| vt_analysis_malicious | int64 | Virus total results marked malicious |
| vt_analysis_undetected | int64 | Virus total results marked undetected |


## Keywords for the Honeypots (model: Honeypot)

| Keyword | Type | Description |
| --- | --- | --- |
| updated_at | Time | Date and time of last update |
| last_checkin | Time | Date and time of last seen |
| default_content_id | int64 | The Content ID that is served by default |
| id | int64 | The ID of the honeypot |
| ip | string | The IP of the honeypot (v4 or v6) |
| auth_token | string | The authentication token |
| created_at | Time | Date and time of creation |


## Keywords for the Manage Queries (model: StoredQuery)

| Keyword | Type | Description |
| --- | --- | --- |
| updated_at | Time | Date and time of last update |
| last_ran_at | Time | Date and time the last time the query ran |
| id | int64 | The ID of the query |
| query | string | The query itself |
| description | string | A description of the query |
| created_at | Time | Date and time of creation |


## Keywords for the Manage tags (model: Tag)

| Keyword | Type | Description |
| --- | --- | --- |
| description | string | A description of the tag |
| created_at | Time | Date and time of creation |
| updated_at | Time | Date and time of last update |
| id | int64 | The ID of the tag |
| name | string | The name of the tag |
| color_html | string | HTML color code |


