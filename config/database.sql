
DROP DATABASE IF EXISTS lophiid;
CREATE DATABASE lophiid;

\connect lophiid

CREATE USER lo WITH PASSWORD 'test';


CREATE TABLE content (
  id              SERIAL PRIMARY KEY,
  name            VARCHAR(256) NOT NULL,
  content         TEXT NOT NULL, -- TODO: remove
  data            BYTEA DEFAULT ''::bytea,
  description     TEXT NOT NULL,
  script          TEXT,
  content_type    VARCHAR(256) NOT NULL,
  server          VARCHAR(256) NOT NULL,
  status_code     STATUS_CODE NOT NULL DEFAULT "200"
  is_default      BOOLEAN DEFAULT FALSE
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);


CREATE TYPE MATCHING_TYPE AS ENUM ('exact', 'prefix', 'suffix', 'contains', 'regex');
CREATE TYPE METHOD_TYPE AS ENUM ('GET', 'POST', 'HEAD', 'TRACE', 'OPTIONS', 'DELETE', 'PUT', 'ANY');
CREATE TYPE STATUS_CODE AS ENUM ('200','301', '302', '400', '401', '403', '404', '500');

CREATE TYPE METADATA_TYPE AS ENUM ('PAYLOAD_LINK', 'DECODED_STRING_BASE64');

CREATE TABLE request_metadata (
  id              SERIAL PRIMARY KEY,
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  request_id      INT,
  type            METADATA_TYPE NOT NULL,
  data            TEXT,
  CONSTRAINT fk_request_id FOREIGN KEY(request_id) REFERENCES request(id)
);

CREATE TABLE content_rule (
  id              SERIAL PRIMARY KEY,
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  host            VARCHAR(512) NOT NULL,
  uri             VARCHAR(2048) NOT NULL,
  uri_matching    MATCHING_TYPE,
  body            VARCHAR(2048),
  body_matching   MATCHING_TYPE,
  method          METHOD_TYPE,
  content_id      INT NOT NULL,
  port            INT NOT NULL DEFAULT 0,
  app_id          INT DEFAULT 0,
  alert           BOOL DEFAULT FALSE,
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
  created_at         TIMESTAMP NOT NULL DEFAULT NOW()
);



-- TODO: store ports here as well. They are already in the proto message.
CREATE TABLE honeypot (
  id                 SERIAL PRIMARY KEY,
  created_at         TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMP NOT NULL DEFAULT NOW(),
  ip                 VARCHAR(52),
  last_checkin       TIMESTAMP NOT NULL DEFAULT NOW(),
  default_content_id INT NOT NULL DEFAULT 0
);

CREATE TABLE app (
  id              SERIAL PRIMARY KEY,
  name            VARCHAR(512),
  vendor          VARCHAR(512),
  version         VARCHAR(512),
  os              VARCHAR(512),
  link            VARCHAR(2048),
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);


CREATE TABLE downloads (
  id              SERIAL PRIMARY KEY,
  original_url    VARCHAR(2048),
  used_url        VARCHAR(2048),
  ip              VARCHAR(52),
  host            VARCHAR(1024),
  content_type    VARCHAR(256),
  sha256sum       VARCHAR(64),
  file_location   VARCHAR(512),
  size            INT,
  times_seen      INT NOT NULL DEFAULT 1,
  port            INT,
  request_id      INT,
  last_request_id INT,
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  last_seen_at    TIMESTAMP NOT NULL DEFAULT NOW(),
  vt_analysis_id  VARCHAR(1024) DEFAULT '',
  CONSTRAINT fk_request_id FOREIGN KEY(request_id) REFERENCES request(id)
);

CREATE TABLE request (
  id              SERIAL PRIMARY KEY,
  proto           VARCHAR(10),
  host            VARCHAR(2048),
  port            INT,
  method          VARCHAR(10),
  uri             VARCHAR(2048),
  path            VARCHAR(2048),
  referer         VARCHAR(2048),
  content_length  INT,
  user_agent      VARCHAR(2048),
  body            BYTEA NOT NULL DEFAULT ''::bytea,
  source_ip       VARCHAR(512),
  source_port     INT,
  raw             TEXT,
  time_received   TIMESTAMP NOT NULL DEFAULT NOW(),
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  honeypot_ip     VARCHAR(15),
  starred         BOOL default FALSE,
  content_id      INT,
  rule_id         INT
);


CREATE TABLE whois (
  id                   SERIAL PRIMARY KEY,
  data                 TEXT,
  ip                   VARCHAR(52),
  created_at           TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMP NOT NULL DEFAULT NOW()
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
CREATE INDEX requests_idx ON request ( time_received desc );
CREATE INDEX requests_port_idx ON request (
  time_received desc,
  port asc
);

CREATE INDEX requests_source_ip_idx ON request (
  time_received desc,
  source_ip desc
);

CREATE INDEX requests_uri_idx ON request (
  time_received desc,
  uri
);

CREATE INDEX requests_content_length_idx ON request (
  time_received desc,
  content_length
);

CREATE INDEX requests_created_at_idx ON request (
  time_received desc,
  created_at DESC
);





