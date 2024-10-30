package constants

// The lophiid version. Needs to be bumped with every release and is used by
// both the agent and the backend.
const LophiidVersion = "0.11.1-alpha"

// IP event sources are used to indicate the source of an IP event. The values
// below need to be kept in sync with IP_EVENT_SOURCE in the database.
const (
	IpEventSourceOther    = "OTHER"
	IpEventSourceVT       = "VT"
	IpEventSourceRule     = "RULE"
	IpEventSourceBackend  = "BACKEND"
	IpEventSourceAnalysis = "ANALYSIS"
	IpEventSourceWhois    = "WHOIS"
)

// This needs to be kept in sync with IP_EVENT_TYPE in the database.
const (
	IpEventCrawl         = "CRAWLED"
	IpEventHostedMalware = "HOSTED_MALWARE"
	IpEventRecon         = "RECONNED"
	IpEventScanned       = "SCANNED"
	IpEventAttacked      = "ATTACKED"
	IpEventBrute         = "BRUTEFORCED"
	IpEventHostC2        = "HOST_C2"
	IpEventRateLimited   = "RATELIMITED"
)

// These constants are the extractor types used in ./pkg/backend/extractors
const (
	ExtractorTypeBase64  = "DECODED_STRING_BASE64"
	ExtractorTypeUnicode = "DECODED_STRING_UNICODE"
	ExtractorTypeLink    = "PAYLOAD_LINK"
	ExtractorTypeTcpLink = "PAYLOAD_TCP_LINK"
)

// This needs to be kept in sync with RESPONDER_TYPE in the database.
const (
	ResponderTypeNone                = "NONE"
	ResponderTypeCommandInjection    = "COMMAND_INJECTION"
	ResponderTypeSourceCodeExecution = "SOURCE_CODE_EXECUTION"
)

// This needs to be kept in sync with RESPONDER_DECODER_TYPE in the database.
const (
	ResponderDecoderTypeNone = "NONE"
	ResponderDecoderTypeUri  = "URI"
	ResponderDecoderTypeHtml = "HTML"
)
