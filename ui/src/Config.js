
export default {
  contentLink: '/content',
  contentSelectedLink: '/content/:contentId',
  rulesLink: '/rules',
  rulesSelectedLink: '/rules/:ruleId',
  appsLink: '/apps',
  requestsLink: '/requests',
  requestsSegmentLink: '/requests/:offset/:limit',
  requestsSegmentLinkName: 'reqSegmentLink',
  backendAddress: 'http://192.168.1.78:8088',
 // backendAddress: 'http://127.0.0.1:8088',
  backendResultOk: 'OK',
  backendResultNotOk: 'ERR',

  // There next 3 need to be in sync with the database enums.
  backendMatchingMethods: ['exact', 'prefix', 'suffix', 'regex', 'contains'],
  contentRuleHTTPMethods: ['ANY' , 'GET', 'POST'],
  //statusCodeValues: [ '200', '301', '302', '400', '401', '403', '404', '500'],
  statusCodeValues: [
    { label: '200 - OK', value: '200' },
    { label: '301 - Permanent redirect', value: '301' },
    { label: '302 - Temporary redirect', value: '302' },
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
