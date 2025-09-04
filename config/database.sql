-- Database initialization script for Docker
-- This runs inside the already-created lophiid database

-- IMPORTANT: CHANGE THE PASSWORD
CREATE USER lo WITH PASSWORD 'CHANGE_ME_TO_SOMETHING_GOOD';

CREATE TYPE MATCHING_TYPE AS ENUM ('none', 'exact', 'prefix', 'suffix', 'contains', 'regex');
CREATE TYPE METHOD_TYPE AS ENUM ('GET', 'POST', 'HEAD', 'TRACE', 'OPTIONS', 'DELETE', 'PUT', 'ANY');
CREATE TYPE STATUS_CODE AS ENUM ('200','301', '302', '400', '401', '403', '404', '500');

CREATE TABLE content (
  id              SERIAL PRIMARY KEY,
  name            VARCHAR(256) NOT NULL,
  data            BYTEA DEFAULT ''::bytea,
  description     TEXT NOT NULL,
  script          TEXT,
  content_type    VARCHAR(256) NOT NULL,
  server          VARCHAR(256) NOT NULL,
  headers         VARCHAR(4096) ARRAY,
  status_code     STATUS_CODE NOT NULL DEFAULT '200',
  created_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  ext_version     INT DEFAULT 1,
  ext_uuid        VARCHAR(36) NOT NULL DEFAULT gen_random_uuid()
);

CREATE TYPE METADATA_TYPE AS ENUM ('PAYLOAD_PING', 'PAYLOAD_LINK', 'PAYLOAD_TCP_LINK', 'PAYLOAD_NETCAT', 'SCRIPT_RESPONSE_BODY', 'DECODED_STRING_BASE64', 'DECODED_STRING_UNICODE');
CREATE TYPE DOWNLOAD_STATUS AS ENUM ('UNKNOWN', 'SCHEDULED', 'DONE');
CREATE TYPE REQUEST_PURPOSE AS ENUM ('UNKNOWN', 'RECON', 'CRAWL', 'ATTACK');
CREATE TYPE RESPONDER_TYPE AS ENUM ('NONE', 'COMMAND_INJECTION', 'SOURCE_CODE_INJECTION');
CREATE TYPE RESPONDER_DECODER_TYPE AS ENUM ('NONE', 'URI', 'HTML');
CREATE TYPE YARA_STATUS_TYPE AS ENUM ('UNKNOWN', 'PENDING', 'DONE', 'FAILED');
CREATE TYPE REVIEW_STATUS_TYPE AS ENUM ('UNREVIEWED', 'REVIEWED_OK', 'REVIEWED_NOK');
CREATE TYPE TRIAGE_STATUS_TYPE AS ENUM ('UNKNOWN', 'PENDING', 'DONE', 'FAILED');

CREATE TABLE request (
  id              SERIAL PRIMARY KEY,
  proto           VARCHAR(10),
  host            VARCHAR(2048),
  port            INT,
  method          VARCHAR(10),
  uri             VARCHAR(2048),
  query           VARCHAR(2048),
  path            VARCHAR(2048),
  referer         VARCHAR(2048),
  content_type    VARCHAR(1024),
  content_length  INT,
  user_agent      VARCHAR(2048),
  body            BYTEA NOT NULL DEFAULT ''::bytea,
  headers         VARCHAR(4096) ARRAY,
  source_ip       VARCHAR(512),
  source_port     INT,
  raw             TEXT,
  raw_response    TEXT,
  time_received   TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  created_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  honeypot_ip     VARCHAR(40),
  starred         BOOL default FALSE,
  content_dynamic BOOL default FALSE,
  has_malware     BOOL default FALSE,
  base_hash       VARCHAR(64) DEFAULT '',
  cmp_hash        VARCHAR(64) DEFAULT '',
  content_id      INT,
  session_id      INT NOT NULL default 0,
  app_id          INT NOT NULL default 0,
  rule_id         INT NOT NULL DEFAULT 0,
  rule_uuid       VARCHAR(36) default ''
);

CREATE TABLE request_description (
  id                 SERIAL PRIMARY KEY,
  created_at         TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at         TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  cmp_hash           VARCHAR(64) DEFAULT '',
  example_request_id INT,
  ai_description     TEXT,
  ai_application     VARCHAR(128),
  ai_vulnerability_type   VARCHAR(128),
  ai_malicious       VARCHAR(6),
  ai_cve             VARCHAR(15),
  ai_has_payload     VARCHAR(6) default '',
  review_status      REVIEW_STATUS_TYPE default 'UNREVIEWED',
  source_model       VARCHAR(256) default 'UNKNOWN',
  triage_status             TRIAGE_STATUS_TYPE default 'UNKNOWN',
  CONSTRAINT fk_example_request_id FOREIGN KEY(example_request_id) REFERENCES request(id)
);


CREATE TABLE content_rule (
  id              SERIAL PRIMARY KEY,
  created_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  uri             VARCHAR(2048) NOT NULL,
  uri_matching    MATCHING_TYPE,
  body            VARCHAR(2048),
  body_matching   MATCHING_TYPE,
  method          METHOD_TYPE,
  content_id      INT NOT NULL,
  port            INT NOT NULL DEFAULT 0,
  ports           INT ARRAY DEFAULT '{}',
  app_id          INT DEFAULT 0,
  app_uuid        VARCHAR(36) default '',
  content_uuid        VARCHAR(36) default '',
  alert           BOOL DEFAULT FALSE,
  request_purpose   REQUEST_PURPOSE default 'UNKNOWN',
  ext_version  INT DEFAULT 1,
  ext_uuid        VARCHAR(36) NOT NULL DEFAULT gen_random_uuid(),
  responder       RESPONDER_TYPE default 'NONE',
  responder_regex VARCHAR(1024) default '',
  responder_decoder RESPONDER_DECODER_TYPE default 'NONE',
  enabled         BOOL DEFAULT TRUE,
  block           BOOL DEFAULT FALSE,
  CONSTRAINT fk_content_id FOREIGN KEY(content_id) REFERENCES content(id)
);

CREATE TABLE vt_ipresult (
  id                 SERIAL PRIMARY KEY,
  ip                 VARCHAR(52),
  whois              TEXT,
  country            VARCHAR(64),
  asn                INT DEFAULT 0,
  as_owner           VARCHAR(512),
  last_analysis_date TIMESTAMP NOT NULL,
  result_harmless    INT DEFAULT 0,
  result_malicious   INT DEFAULT 0,
  result_suspicious  INT DEFAULT 0,
  result_undetected  INT DEFAULT 0,
  result_timeout     INT DEFAULT 0,
  created_at         TIMESTAMP NOT NULL DEFAULT (timezone('utc', now()))
);

CREATE TABLE request_metadata (
  id              SERIAL PRIMARY KEY,
  created_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  request_id      INT,
  type            METADATA_TYPE NOT NULL,
  data            TEXT,
  CONSTRAINT fk_request_id FOREIGN KEY(request_id) REFERENCES request(id)
);



-- TODO: store ports here as well. They are already in the proto message.
CREATE TABLE honeypot (
  id                 SERIAL PRIMARY KEY,
  created_at         TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at         TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  ip                 VARCHAR(52),
  version            VARCHAR(64) NOT NULL DEFAULT '',
  auth_token         VARCHAR(64) NOT NULL DEFAULT '',
  last_checkin       TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  default_content_id INT NOT NULL DEFAULT 0,
  ports              INT ARRAY,
  ssl_ports          INT ARRAY,
  cves            VARCHAR(15) ARRAY
);


CREATE TABLE app (
  id              SERIAL PRIMARY KEY,
  name            VARCHAR(512),
  vendor          VARCHAR(512),
  version         VARCHAR(512),
  os              VARCHAR(512),
  link            VARCHAR(2048),
  created_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  ext_version  INT DEFAULT 1,
  ext_uuid        VARCHAR(36) NOT NULL DEFAULT gen_random_uuid(),
  cves            VARCHAR(15) ARRAY
);

CREATE TABLE session (
  id              SERIAL PRIMARY KEY,
  active          BOOL DEFAULT FALSE,
  ip              VARCHAR(52) NOT NULL,
  started_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  created_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  ended_at        TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now()))
);



CREATE TABLE downloads (
  id              SERIAL PRIMARY KEY,
  original_url    VARCHAR(2048),
  used_url        VARCHAR(2048),
  ip              VARCHAR(52),
  honeypot_ip     VARCHAR(52) default '',
  source_ip       VARCHAR(52) default '',
  host            VARCHAR(1024),
  content_type    VARCHAR(256),
  detected_content_type VARCHAR(256),
  sha256sum       VARCHAR(64),
  file_location   VARCHAR(512),
  size            INT,
  times_seen      INT NOT NULL DEFAULT 1,
  port            INT,
  request_id      INT,
  last_request_id INT,
  created_at      TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  last_seen_at    TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  raw_http_response  TEXT,
  vt_file_analysis_result VARCHAR(1024) ARRAY,
  vt_url_analysis_id  VARCHAR(1024) DEFAULT '',
  vt_file_analysis_id  VARCHAR(1024) DEFAULT '',
  vt_file_analysis_submitted  BOOL default false,
  vt_file_analysis_done  BOOL default false,
  vt_analysis_harmless   INT DEFAULT 0,
  vt_analysis_malicious  INT DEFAULT 0,
  vt_analysis_suspicious INT DEFAULT 0,
  vt_analysis_undetected INT DEFAULT 0,
  vt_analysis_timeout    INT DEFAULT 0,
  status         DOWNLOAD_STATUS default 'UNKNOWN',
  yara_status    YARA_STATUS_TYPE default 'UNKNOWN',
  yara_last_scan TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  yara_scanned_unpacked BOOLEAN default FALSE,
  yara_description TEXT,
  source_download_id INT default 0,
  CONSTRAINT fk_request_id FOREIGN KEY(request_id) REFERENCES request(id)
);


CREATE TABLE yara (
  id                        SERIAL PRIMARY KEY,
  download_id               INT,
  identifier                VARCHAR(2048),
  author                    VARCHAR(2048),
  description               VARCHAR(4096),
  reference                 VARCHAR(2048),
  date                      VARCHAR(64),
  eid                        VARCHAR(256),
  malpedia_reference        VARCHAR(2048),
  malpedia_version          VARCHAR(64),
  malpedia_license          VARCHAR(256),
  malpedia_sharing          VARCHAR(32),
  metadata                  VARCHAR(4096) ARRAY,
  tags                      VARCHAR(512) ARRAY,
  created_at                TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at                TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  CONSTRAINT fk_download_id FOREIGN KEY(download_id) REFERENCES downloads(id) ON DELETE CASCADE
);

CREATE TABLE p0f_result (
  id                        SERIAL PRIMARY KEY,
  ip                        VARCHAR(52),
  first_seen_time           TIMESTAMP,
  last_seen_time            TIMESTAMP,
  total_count               INT DEFAULT 0,
  uptime_minutes            INT DEFAULT 0,
  uptime_days               INT DEFAULT 0,
  distance                  INT DEFAULT 0,
  last_nat_detection_time   TIMESTAMP,
  last_os_change_time       TIMESTAMP,
  os_match_quality          INT DEFAULT 0,
  os_name                   VARCHAR(32),
  os_version                VARCHAR(32),
  http_name                 VARCHAR(32),
  http_flavor               VARCHAR(32),
  language                  VARCHAR(32),
  link_type                 VARCHAR(32),
  created_at                TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at                TIMESTAMP NOT NULL DEFAULT (timezone('utc', now()))
);

CREATE TABLE stored_query (
  id                   SERIAL PRIMARY KEY,
  query                VARCHAR(8192),
  description          TEXT,
  created_at           TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at           TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  record_count         INT DEFAULT 0,
  times_run            INT DEFAULT 0,
  last_ran_at          TIMESTAMP NOT NULL DEFAULT (timezone('utc', now()))
);

CREATE TABLE tag (
  id                   SERIAL,
  name                 VARCHAR(64) NOT NULL,
  color_html           VARCHAR(8),
  description          TEXT,
  created_at           TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at           TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  PRIMARY KEY(id)
);

-- If a query or a tag gets deleted, we also want this one gone.
CREATE TABLE tag_per_query (
  id SERIAL PRIMARY KEY,
  tag_id INT,
  query_id INT,
  CONSTRAINT fk_per_query_tag_id
    FOREIGN KEY (tag_id) REFERENCES tag(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_per_query_stored_query_id
    FOREIGN KEY (query_id) REFERENCES stored_query(id)
    ON DELETE CASCADE
);

-- If a request or a tag gets deleted, we also want this one gone.
CREATE TABLE tag_per_request (
  id SERIAL,
  tag_id INT,
  request_id INT,
  tag_per_query_id INT,
  CONSTRAINT fk_per_request_tag_id
    FOREIGN KEY (tag_id) REFERENCES tag(id)
    ON DELETE CASCADE,
  -- this one is important. We want to optionally store the ID of tag_per_query
  -- entries and delete on cascade here. This so that when a tag is removed from
  -- a query, we will also delete all the tags that that query put on requests.
  CONSTRAINT fk_tag_per_query_id
    FOREIGN KEY (tag_per_query_id) REFERENCES tag_per_query(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_per_request_request_id
    FOREIGN KEY (request_id) REFERENCES request(id)
    ON DELETE CASCADE
);

-- The whois.data column was used for old whois data. The rdap columm replaces
-- it.
CREATE TABLE whois (
  id                   SERIAL PRIMARY KEY,
  data                 TEXT,
  rdap                 BYTEA NOT NULL DEFAULT ''::bytea,
  ip                   VARCHAR(52),
  country              VARCHAR(128),
  created_at           TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at           TIMESTAMP NOT NULL DEFAULT (timezone('utc', now()))
);


-- These need to be kept in sync with pkg/util/constants/shared_constants.go
CREATE TYPE IP_EVENT_TYPE AS ENUM ('UNKNOWN', 'PING', 'TRAFFIC_CLASS', 'HOSTED_MALWARE', 'SENT_MALWARE', 'RATELIMITED', 'HOST_C2');
CREATE TYPE IP_EVENT_SUB_TYPE AS ENUM ('UNKNOWN', 'NONE', 'MALWARE_NEW', 'MALWARE_OLD', 'IP_RATE_WINDOW', 'IP_RATE_BUCKET', 'URI_RATE_WINDOW', 'URI_RATE_BUCKET', 'TC_SCANNED', 'TC_ATTACKED', 'TC_RECONNED', 'TC_BRUTEFORCED', 'TC_CRAWLED', 'TC_MALICIOUS', 'SUCCESS', 'FAILURE');
CREATE TYPE IP_EVENT_SOURCE AS ENUM ('OTHER', 'VT', 'RULE', 'BACKEND', 'ANALYSIS', 'WHOIS', 'AI');
CREATE TYPE IP_EVENT_REF_TYPE AS ENUM ('UNKNOWN', 'NONE', 'REQUEST_ID', 'RULE_ID', 'CONTENT_ID', 'VT_ANALYSIS_ID', 'DOWNLOAD_ID', 'REQUEST_DESCRIPTION_ID', 'REQUEST_SOURCE_IP', 'SESSION_ID', 'APP_ID');
CREATE TABLE ip_event (
  id                     SERIAL PRIMARY KEY,
  ip                     VARCHAR(52),
  domain                 VARCHAR(256),
  details                VARCHAR(4096),
  note                   VARCHAR(4096),
  count                  INTEGER default 0,
  type                   IP_EVENT_TYPE DEFAULT 'UNKNOWN',
  subtype                IP_EVENT_SUB_TYPE DEFAULT 'NONE',
  request_id             INTEGER,   -- optional
  source                 IP_EVENT_SOURCE default 'OTHER',
  source_ref             VARCHAR(512),
  source_ref_type        IP_EVENT_REF_TYPE default 'NONE',
  honeypot_ip            VARCHAR(52),
  first_seen_at          TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  created_at             TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  updated_at             TIMESTAMP NOT NULL DEFAULT (timezone('utc', now()))
);

GRANT ALL PRIVILEGES ON content TO lo;
GRANT ALL PRIVILEGES ON content_id_seq TO lo;
GRANT ALL PRIVILEGES ON content_rule TO lo;
GRANT ALL PRIVILEGES ON content_rule_id_seq TO lo;
GRANT ALL PRIVILEGES ON request TO lo;
GRANT ALL PRIVILEGES ON request_id_seq TO lo;
GRANT ALL PRIVILEGES ON app TO lo;
GRANT ALL PRIVILEGES ON app_id_seq TO lo;
GRANT ALL PRIVILEGES ON request_metadata TO lo;
GRANT ALL PRIVILEGES ON request_metadata_id_seq TO lo;
GRANT ALL PRIVILEGES ON downloads TO lo;
GRANT ALL PRIVILEGES ON downloads_id_seq TO lo;
GRANT ALL PRIVILEGES ON whois TO lo;
GRANT ALL PRIVILEGES ON whois_id_seq TO lo;
GRANT ALL PRIVILEGES ON honeypot TO lo;
GRANT ALL PRIVILEGES ON honeypot_id_seq TO lo;
GRANT ALL PRIVILEGES ON vt_ipresult TO lo;
GRANT ALL PRIVILEGES ON vt_ipresult_id_seq TO lo;
GRANT ALL PRIVILEGES ON stored_query TO lo;
GRANT ALL PRIVILEGES ON stored_query_id_seq TO lo;
GRANT ALL PRIVILEGES ON tag TO lo;
GRANT ALL PRIVILEGES ON tag_id_seq TO lo;
GRANT ALL PRIVILEGES ON tag_per_query TO lo;
GRANT ALL PRIVILEGES ON tag_per_query_id_seq TO lo;
GRANT ALL PRIVILEGES ON tag_per_request TO lo;
GRANT ALL PRIVILEGES ON tag_per_request_id_seq TO lo;
GRANT ALL PRIVILEGES ON p0f_result TO lo;
GRANT ALL PRIVILEGES ON p0f_result_id_seq TO lo;
GRANT ALL PRIVILEGES ON ip_event TO lo;
GRANT ALL PRIVILEGES ON ip_event_id_seq TO lo;
GRANT ALL PRIVILEGES ON session TO lo;
GRANT ALL PRIVILEGES ON session_id_seq TO lo;
GRANT ALL PRIVILEGES ON request_description TO lo;
GRANT ALL PRIVILEGES ON request_description_id_seq TO lo;
GRANT ALL PRIVILEGES ON yara TO lo;
GRANT ALL PRIVILEGES ON yara_id_seq TO lo;


CREATE INDEX session_ip ON session (
  started_at desc,
  active,
  ip
);

CREATE INDEX requests_cmp_ruleuuid_idx ON request (
  time_received desc,
  rule_uuid
);

CREATE INDEX requests_starred_idx ON request (
  starred
);


CREATE INDEX requests_per_created_at ON request (
  created_at desc
);


CREATE INDEX requests_cmp_hash_idx ON request (
  time_received desc,
  cmp_hash
);

CREATE INDEX requests_session_idx ON request (
  time_received desc,
  session_id desc
);

CREATE INDEX requests_idx ON request ( time_received desc );
CREATE INDEX requests_port_idx ON request (
  time_received desc,
  port asc
);

CREATE INDEX requests_source_ip_idx ON request (
  time_received desc,
  source_ip desc
);

CREATE INDEX requests_honeypot_ip_idx ON request (
  time_received desc,
  honeypot_ip
);

CREATE INDEX requests_uri_idx ON request (
  time_received desc,
  uri
);

CREATE INDEX requests_base_hash_idx ON request (
  time_received desc,
  base_hash
);


CREATE INDEX requests_content_length_idx ON request (
  time_received desc,
  content_length
);

CREATE INDEX requests_created_at_idx ON request (
  time_received desc,
  created_at DESC
);


CREATE INDEX query_id_tag_per_query_idx ON tag_per_query (
  query_id DESC
);

CREATE INDEX request_id_tag_per_request_idx ON tag_per_request (
  request_id DESC
);

CREATE INDEX ip_per_whois_idx ON whois (
  ip
);

CREATE INDEX request_id_per_request_metdata ON request_metadata (
  request_id DESC
);

CREATE INDEX request_description_status_idx ON request_description (
  created_at DESC,
  triage_status
);
