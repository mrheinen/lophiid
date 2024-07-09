

# Search keywords

This document is automatically generated from the structs in database.go
an describes all the different keywords that can be searched per model /
page in the UI.

Note that in the UI, on pages where search is available, the same
information can be found by clicking on ? icon in the left corner of
the search bar.

## Keywords for the Requests (model: Request)

| Keyword | Type | Description |
| ___ | ___ | ___ |
| content_id | int64 | The Content ID that was served |
| content_dynamic | bool | A bool indicating if the Content is dynamic (script based) |
| base_hash | string | A base hash to find similar requests |
| uri | string | The request URI |
| content_type | string | The Content-Type header value |
| proto | string | The HTTP protocol (e.g. HTTP/1.0) |
| starred | bool | A bool if the request is starred |
| referer | string | The referer header value |
| content_length | int64 | The Content-Length header value |
| user_agent | string | The User-Agent value |
| source_ip | string | The HTTP client source IP |
| source_port | int64 | The HTTP client source port |
| path | string | The URL path |
| host | string | The HTTP Host header value |
| port | int64 | The HTTP server port |
| updated_at | Time | The date and time of the last update |
| id | int64 | The ID of the request |
| honeypot_ip | string | The honeypot IP that received the request |
| raw_response | string | The raw HTTP response (only used for scripted Content) |
| created_at | Time | The date and time of creation |
| rule_id | int64 | The ID of the rule that matched this request |
| method | string | The HTTP method (e.g. GET, POST, PUT, DELETE, ...) |
| time_received | Time | The date and time the honeypot received the request |
| headers | FlatArray[string] | The client HTTP headers |
| body |  | The request body |
| raw | string | The raw HTTP request |
| query | string | The query section of the URL |


## Keywords for the Content (model: Content)

| Keyword | Type | Description |
| ___ | ___ | ___ |
| created_at | Time | time.Time of creation |
| headers | FlatArray[string] | The content HTTP headers |
| data |  | The content data itself |
| name | string | The content name |
| description | string | The content description |
| content_type | string | The HTTP content-type |
| server | string | The HTTP server with which the content is served |
| status_code | string | The HTTP status code |
| script | string | The content script |
| id | int64 | The ID of the content |
| updated_at | Time | time.Time of last update |


## Keywords for the Rules (model: ContentRule)

| Keyword | Type | Description |
| ___ | ___ | ___ |
| alert | bool | A bool (0 or 1) indicating if the rule should alert |
| id | int64 | The rule ID |
| uri | string | The URI matching string |
| port | int64 | The TCP port the rue matches on. |
| content_id | int64 | The ID of the Content this rule serves |
| app_id | int64 | The ID of the application for which this rule is |
| updated_at | Time | Last update date of the rule |
| body | string | The body matching string |
| method | string | The HTTP method the rule matches on |
| uri_matching | string | The URI matching method (exact, regex, ..) |
| body_matching | string | The body matching method |
| created_at | Time | Creation date of the rule |


## Keywords for the Apps (model: Application)

| Keyword | Type | Description |
| ___ | ___ | ___ |
| link | string | A reference link |
| created_at | Time | Date and time of creation |
| updated_at | Time | Date and time of last update |
| id | int64 | The ID of the application |
| name | string | The application name |
| version | string | The application version |
| vendor | string | The application vendor |
| os | string | The OS on which the application runs |


## Keywords for the Downloads (model: Download)

| Keyword | Type | Description |
| ___ | ___ | ___ |
| honeypot_ip | string | Honeypot IP used for download |
| times_seen | int64 | How often this was seen |
| raw_http_response | string | The HTTP response of the download server |
| vt_analysis_undetected | int64 | Virus total results marked undetected |
| content_type | string | The content type (mime) of the download (reported by server) |
| detected_content_type | string | The content type (mime) as detected |
| used_url | string | Actually used download URL |
| last_request_id | int64 | The request ID of the last request with this download |
| vt_url_analysis_id | string | The virus total URL analysis ID |
| vt_analysis_harmless | int64 | Virus total results marked harmless |
| vt_analysis_malicious | int64 | Virus total results marked malicious |
| port | int64 | Server port |
| created_at | Time | Date and time of creation |
| original_url | string | Original download URL |
| sha256sum | string | SHA256 sum of the download |
| request_id | int64 | ID of the request where the download originated from |
| size | int64 | Size in bytes of the download |
| ip | string | Download server IP |
| host | string | The Host header value used in downloading |
| file_location | string | The file location of the download |
| vt_file_analysis_id | string | The virus total file analysis ID |
| vt_analysis_suspicious | int64 | Virus total results marked suspicious |
| id | int64 | The ID of the download |
| last_seen_at | Time | Date and time of last update |


## Keywords for the Honeypots (model: Honeypot)

| Keyword | Type | Description |
| ___ | ___ | ___ |
| id | int64 | The ID of the honeypot |
| ip | string | The IP of the honeypot (v4 or v6) |
| auth_token | string | The authentication token |
| created_at | Time | Date and time of creation |
| updated_at | Time | Date and time of last update |
| last_checkin | Time | Date and time of last seen |
| default_content_id | int64 | The Content ID that is served by default |


## Keywords for the Manage Queries (model: StoredQuery)

| Keyword | Type | Description |
| ___ | ___ | ___ |
| id | int64 | The ID of the query |
| query | string | The query itself |
| description | string | A description of the query |
| created_at | Time | Date and time of creation |
| updated_at | Time | Date and time of last update |
| last_ran_at | Time | Date and time the last time the query ran |


## Keywords for the Manage tags (model: Tag)

| Keyword | Type | Description |
| ___ | ___ | ___ |
| created_at | Time | Date and time of creation |
| updated_at | Time | Date and time of last update |
| id | int64 | The ID of the tag |
| name | string | The name of the tag |
| color_html | string | HTML color code |
| description | string | A description of the tag |


