

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
| base_hash | string | A base hash to find similar requests |
| body |  | The request body |
| content_dynamic | bool | A bool indicating if the Content is dynamic (script based) |
| content_id | int64 | The Content ID that was served |
| content_length | int64 | The Content-Length header value |
| content_type | string | The Content-Type header value |
| created_at | Time | The date and time of creation |
| headers | FlatArray[string] | The client HTTP headers |
| honeypot_ip | string | The honeypot IP that received the request |
| host | string | The HTTP Host header value |
| id | int64 | The ID of the request |
| method | string | The HTTP method (e.g. GET, POST, PUT, DELETE, ...) |
| path | string | The URL path |
| port | int64 | The HTTP server port |
| proto | string | The HTTP protocol (e.g. HTTP/1.0) |
| query | string | The query section of the URL |
| raw | string | The raw HTTP request |
| raw_response | string | The raw HTTP response (only used for scripted Content) |
| referer | string | The referer header value |
| rule_id | int64 | The ID of the rule that matched this request |
| rule_uuid | string | The UUID of the rule that matched this request |
| source_ip | string | The HTTP client source IP |
| source_port | int64 | The HTTP client source port |
| starred | bool | A bool if the request is starred |
| time_received | Time | The date and time the honeypot received the request |
| updated_at | Time | The date and time of the last update |
| uri | string | The request URI |
| user_agent | string | The User-Agent value |


## Keywords for the Content (model: Content)

| Keyword | Type | Description |
| --- | --- | --- |
| content_type | string | The HTTP content-type |
| created_at | Time | time.Time of creation |
| data | YammableBytes | The content data itself |
| description | string | The content description |
| ext_uuid | string | The external unique ID of the content |
| ext_version | int64 | The external numerical version of the content |
| headers | FlatArray[string] | The content HTTP headers |
| id | int64 | The ID of the content |
| name | string | The content name |
| script | string | The content script |
| server | string | The HTTP server with which the content is served |
| status_code | string | The HTTP status code |
| updated_at | Time | time.Time of last update |


## Keywords for the Rules (model: ContentRule)

| Keyword | Type | Description |
| --- | --- | --- |
| alert | bool | A bool (0 or 1) indicating if the rule should alert |
| app_id | int64 | The ID of the application for which this rule is |
| app_uuid | string | The external UUID of the related app |
| body | string | The body matching string |
| body_matching | string | The body matching method |
| content_id | int64 | The ID of the Content this rule serves |
| content_uuid | string | The external UUID of the related content |
| created_at | Time | Creation date of the rule |
| ext_uuid | string | The external unique ID of the rule |
| ext_version | int64 | The external numerical version of the rule |
| id | int64 | The rule ID |
| method | string | The HTTP method the rule matches on |
| port | int64 | The TCP port the rue matches on. |
| request_purpose | string | The purpose of the request (e.g. UNKNOWN, RECON, CRAWL, ATTACK) |
| responder | string | The responder type for this rule (e.g. COMMAND_INJECTION) |
| responder_decoder | string | The responder decoder to use (e.g. NONE, URI, HTML) |
| responder_regex | string | The responder regex to grab the relevant bits |
| updated_at | Time | Last update date of the rule |
| uri | string | The URI matching string |
| uri_matching | string | The URI matching method (exact, regex, ..) |


## Keywords for the Apps (model: Application)

| Keyword | Type | Description |
| --- | --- | --- |
| created_at | Time | Date and time of creation |
| cves | FlatArray[string] | Related Mitre CVEs |
| ext_uuid | string | The external unique ID |
| ext_version | int64 | The external numerical version |
| id | int64 | The ID of the application |
| link | string | A reference link |
| name | string | The application name |
| os | string | The OS on which the application runs |
| updated_at | Time | Date and time of last update |
| vendor | string | The application vendor |
| version | string | The application version |


## Keywords for the Downloads (model: Download)

| Keyword | Type | Description |
| --- | --- | --- |
| content_type | string | The content type (mime) of the download (reported by server) |
| created_at | Time | Date and time of creation |
| detected_content_type | string | The content type (mime) as detected |
| file_location | string | The file location of the download |
| honeypot_ip | string | Honeypot IP used for download |
| host | string | The Host header value used in downloading |
| id | int64 | The ID of the download |
| ip | string | Download server IP |
| last_request_id | int64 | The request ID of the last request with this download |
| last_seen_at | Time | Date and time of last update |
| original_url | string | Original download URL |
| port | int64 | Server port |
| raw_http_response | string | The HTTP response of the download server |
| request_id | int64 | ID of the request where the download originated from |
| sha256sum | string | SHA256 sum of the download |
| size | int64 | Size in bytes of the download |
| times_seen | int64 | How often this was seen |
| used_url | string | Actually used download URL |
| vt_analysis_harmless | int64 | Virus total results marked harmless |
| vt_analysis_malicious | int64 | Virus total results marked malicious |
| vt_analysis_suspicious | int64 | Virus total results marked suspicious |
| vt_analysis_undetected | int64 | Virus total results marked undetected |
| vt_file_analysis_id | string | The virus total file analysis ID |
| vt_url_analysis_id | string | The virus total URL analysis ID |


## Keywords for the Honeypots (model: Honeypot)

| Keyword | Type | Description |
| --- | --- | --- |
| auth_token | string | The authentication token |
| created_at | Time | Date and time of creation |
| default_content_id | int64 | The Content ID that is served by default |
| id | int64 | The ID of the honeypot |
| ip | string | The IP of the honeypot (v4 or v6) |
| last_checkin | Time | Date and time of last seen |
| updated_at | Time | Date and time of last update |
| version | string | The honeypot version |


## Keywords for the Manage Queries (model: StoredQuery)

| Keyword | Type | Description |
| --- | --- | --- |
| created_at | Time | Date and time of creation |
| description | string | A description of the query |
| id | int64 | The ID of the query |
| last_ran_at | Time | Date and time the last time the query ran |
| query | string | The query itself |
| updated_at | Time | Date and time of last update |


## Keywords for the Manage tags (model: Tag)

| Keyword | Type | Description |
| --- | --- | --- |
| color_html | string | HTML color code |
| created_at | Time | Date and time of creation |
| description | string | A description of the tag |
| id | int64 | The ID of the tag |
| name | string | The name of the tag |
| updated_at | Time | Date and time of last update |


## Keywords for the Manage IP events (model: IpEvent)

| Keyword | Type | Description |
| --- | --- | --- |
| count | int64 | How often this event was seen |
| created_at | Time | When the event was created in the database |
| details | string | Any additional details about the event |
| domain | string | The domain for the IP |
| first_seen_at | Time | When the event was first seen |
| honeypot_ip | string | The honeypot IP |
| ip | string | The source IP |
| request_id | int64 | The ID of a request related to the event |
| source | string | The source of the event |
| source_ref | string | A reference related to the source of the event |
| subtype | string | The subtype of the event (e.g. RCE, LFI) |
| type | string | The type of event (e.g. ATTACKED, CRAWLED) |
| updated_at | Time | Last time the event was updated |


