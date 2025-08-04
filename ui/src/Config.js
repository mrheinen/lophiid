export default {
  contentLink: '/content',
  contentSegmentLink: '/content/:offset/:limit',
  rulesLink: '/rules',
  rulesSegmentLink: '/rules/:offset/:limit',
  appsLink: '/apps',
  appsSegmentLink: '/apps/:offset/:limit',
  downloadsLink: '/downloads',
  downloadsSegmentLink: '/downloads/:offset/:limit',
  eventLink: '/events',
  eventSegmentLink: '/events/:offset/:limit',
  requestsLink: '/requests',
  honeypotsLink: '/honeypot',
  honeypotsSegmentLink: '/honeypot/:offset/:limit',
  storedqueryLink: '/query',
  storedquerySegmentLink: '/query/:offset/:limit',
  yaraLink: '/yara',
  yaraSegmentLink: '/yara/:offset/:limit',
  tagsLink: '/tag',
  statsLink: '/stats',
  datamodelDocLink: '/datamodel/doc',
  tagsSegmentLink: '/tag/:offset/:limit',
  requestsSegmentLink: '/requests/:offset/:limit',
  requestsSegmentLinkName: 'reqSegmentLink',
  backendAddress: '/api',
  backendResultOk: 'OK',
  backendResultNotOk: 'ERR',
  reviewStatusOk: "REVIEWED_OK",
  reviewStatusNok: "REVIEWED_NOK",
  reviewStatusNew: "UNREVIEWED",

  // IP event source ref types
  ipEventSourceRefRuleId: 'RULE_ID',
  ipEventSourceRefDownloadId: 'DOWNLOAD_ID',
  ipEventSourceRefRequestId: 'REQUEST_ID',
  ipEventSourceRefSessionId: 'SESSION_ID',
  ipEventSourceRefContentId: 'CONTENT_ID',
  ipEventSourceRefReqDescriptionId: 'REQUEST_DESCRIPTION_ID',

  downloadYaraStatusPending: 'PENDING',
  downloadYaraStatusDone: 'DONE',


  // There next 5 need to be in sync with the database enums.
  backendMatchingMethods: ['none', 'exact', 'prefix', 'suffix', 'regex', 'contains'],
  contentRuleRequestPurposes: ['UNKNOWN', 'RECON', 'CRAWL', 'ATTACK'],
  contentRuleHTTPMethods: ['ANY' , 'GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE'],
  ruleResponderTypes: ['NONE', 'COMMAND_INJECTION', 'SOURCE_CODE_INJECTION'],
  ruleResponderDecoders: ['NONE', 'URI', 'HTML'],

  statusCodeValues: [
    { label: '200 - OK', value: '200' },
    { label: '301 - Permanent redirect', value: '301' },
    { label: '302 - Temporary redirect', value: '302' },
    { label: '400 - Bad request', value: '400' },
    { label: '401 - Unauthorized', value: '401' },
    { label: '403 - Access denied', value: '403' },
    { label: '404 - Not found', value: '404' },
    { label: '500 - Server error', value: '500' }
  ],

  // Auto complete items
  contentTypeValues: [
    "text/plain; charset=UTF-8",
    "text/html; charset=UTF-8",
    "text/xml; charset=UTF-8",
    "text/css; charset=UTF-8",
    "text/csv; charset=UTF-8",
    "text/javascript",
    "application/json",
    "application/pdf",
    "application/zip",
  ],

  readableContentTypeValues: [
    "text/plain",
    "text/html",
    "text/xml",
    "text/css",
    "text/csv",
    "text/plain; charset=UTF-8",
    "text/html; charset=UTF-8",
    "text/xml; charset=UTF-8",
    "text/css; charset=UTF-8",
    "text/csv; charset=UTF-8",
    "text/javascript",
    "application/json",
  ],
  serverValues: [
    "Apache",
    "Apache/2.4.52",
    "nginx",
    "nginx/1.23.4",
    "ECS (dce/26CD)",
  ],


};
