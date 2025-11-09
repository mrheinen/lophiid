package constants

// The lophiid version. Needs to be bumped with every release and is used by
// both the agent and the backend.
const LophiidVersion = "0.50.1-alpha"

// IP event sources are used to indicate the source of an IP event. The values
// below need to be kept in sync with IP_EVENT_SOURCE in the database.
const (
	IpEventSourceOther    = "OTHER"
	IpEventSourceVT       = "VT"
	IpEventSourceRule     = "RULE"
	IpEventSourceBackend  = "BACKEND"
	IpEventSourceAnalysis = "ANALYSIS"
	IpEventSourceWhois    = "WHOIS"
	IpEventSourceAI       = "AI"
	IpEventSourceAgent    = "AGENT"
)

// This needs to be kept in sync with IP_EVENT_TYPE in the database.
const (
	IpEventHostedMalware = "HOSTED_MALWARE"
	IpEventSentMalware   = "SENT_MALWARE"
	IpEventTrafficClass  = "TRAFFIC_CLASS"
	IpEventHostC2        = "HOST_C2"
	IpEventRateLimited   = "RATELIMITED"
	IpEventPing          = "PING"
)

// This needs to be kept in sync with IP_EVENT_SUB_TYPE in the database.
const (
	IpEventSubTypeUnknown = "UNKNOWN"
	IpEventSubTypeNone    = "NONE"

	IpEventSubTypeMalwareNew = "MALWARE_NEW"
	IpEventSubTypeMalwareOld = "MALWARE_OLD"

	IpEventSubTypeRateIPWindow  = "IP_RATE_WINDOW"
	IpEventSubTypeRateIPBucket  = "IP_RATE_BUCKET"
	IpEventSubTypeRateURIWindow = "URI_RATE_WINDOW"
	IpEventSubTypeRateURIBucket = "URI_RATE_BUCKET"

	IpEventSubTypeTrafficClassScanned   = "TC_SCANNED"
	IpEventSubTypeTrafficClassAttacked  = "TC_ATTACKED"
	IpEventSubTypeTrafficClassRecon     = "TC_RECONNED"
	IpEventSubTypeTrafficClassBrute     = "TC_BRUTEFORCED"
	IpEventSubTypeTrafficClassCrawl     = "TC_CRAWLED"
	IpEventSubTypeTrafficClassMalicious = "TC_MALICIOUS"

	IpEventSubTypeSuccess = "SUCCESS"
	IpEventSubTypeFailure = "FAILURE"
)

// These need to be kept in sync with IP_EVENT_REF_TYPE in the database.
const (
	IpEventRefTypeUnknown              = "UNKNOWN"
	IpEventRefTypeNone                 = "NONE"
	IpEventRefTypeRequestId            = "REQUEST_ID"
	IpEventRefTypeRuleId               = "RULE_ID"
	IpEventRefTypeContentId            = "CONTENT_ID"
	IpEventRefTypeAppId                = "APP_ID"
	IpEventRefTypeVtAnalysisId         = "VT_ANALYSIS_ID"
	IpEventRefTypeRequestSourceIp      = "REQUEST_SOURCE_IP"
	IpEventRefTypeSessionId            = "SESSION_ID"
	IpEventRefTypeDownloadId           = "DOWNLOAD_ID"
	IpEventRefTypeRequestDescriptionId = "REQUEST_DESCRIPTION_ID"
)

// These constants are the extractor types used in ./pkg/backend/extractors
const (
	ExtractorTypeBase64  = "DECODED_STRING_BASE64"
	ExtractorTypeUnicode = "DECODED_STRING_UNICODE"
	ExtractorTypeLink    = "PAYLOAD_LINK"
	ExtractorTypePing    = "PAYLOAD_PING"
	ExtractorTypeTcpLink = "PAYLOAD_TCP_LINK"
)

// This needs to be kept in sync with RESPONDER_TYPE in the database.
const (
	ResponderTypeNone                = "NONE"
	ResponderTypeCommandInjection    = "COMMAND_INJECTION"
	ResponderTypeSourceCodeExecution = "SOURCE_CODE_EXECUTION"
	ResponderTypeAuto                = "AUTO"
	ResponderTypeHelpfulAI           = "HELPFUL_AI"
)

// This needs to be kept in sync with RESPONDER_DECODER_TYPE in the database.
const (
	ResponderDecoderTypeNone = "NONE"
	ResponderDecoderTypeUri  = "URI"
	ResponderDecoderTypeHtml = "HTML"
)

// These need to be kept in sync with REVIEW_STATUS_TYPE in the database
const (
	DescriberUnreviewed  = "UNREVIEWED"
	DescriberReviewedOk  = "REVIEWED_OK"
	DescriberReviewedNok = "REVIEWED_NOK"
)

// These need to be kept in sync with TRIAGE_STATUS_TYPE in the database
const (
	TriageStatusTypePending = "PENDING"
	TriageStatusTypeUnknown = "UNKNOWN"
	TriageStatusTypeDone    = "DONE"
	TriageStatusTypeFailed  = "FAILED"
)

// These need to be kept in sync with YARA_STATUS_TYPE in the database
const (
	YaraStatusTypeUnknown = "UNKNOWN"
	YaraStatusTypePending = "PENDING"
	YaraStatusTypeDone    = "DONE"
	YaraStatusTypeFailed  = "FAILED"
)

const (
	LLMClientMessageUser      = "user"
	LLMClientMessageSystem    = "system"
	LLMClientMessageModel     = "model"
	LLMClientMessageAssistant = "assistant"
)

const (
	TriagePayloadTypeUnknown      = "UNKNOWN"
	TriagePayloadTypeShellCommand = "SHELL_COMMAND"
	TriagePayloadTypeFileAccess   = "FILE_ACCESS"
	TriagePayloadTypeCodeExec     = "CODE_EXECUTION"
)

// Template constants used by the templator.
const (
	TemplatorMacroExpiresDate = "%%COOKIE_EXP_DATE%%"
	TemplatorMacroSourceIP    = "%%REQUEST_SOURCE_IP%%"
	TemplatorMacroSourcePort  = "%%REQUEST_SOURCE_PORT%%"
	TemplatorMacroHoneypotIP  = "%%REQUEST_HONEYPOT_IP%%"
	TemplatorMacroPort        = "%%REQUEST_PORT%%"
)
