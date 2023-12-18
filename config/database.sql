
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
  content_type    VARCHAR(256) NOT NULL,
  server          VARCHAR(256) NOT NULL,
  status_code     STATUS_CODE NOT NULL DEFAULT "200"
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);


CREATE TYPE MATCHING_TYPE AS ENUM ('exact', 'prefix', 'suffix', 'contains', 'regex');
CREATE TYPE METHOD_TYPE AS ENUM ('GET', 'POST', 'HEAD', 'TRACE', 'OPTIONS', 'DELETE', 'PUT', 'ANY');
CREATE TYPE STATUS_CODE AS ENUM ('200','301', '302', '400', '401', '403', '404', '500');
--  Attacker is the origator from the attack. Delivery is the host with the
--  malware (e.g. where it's wget from).
CREATE TYPE ACTOR_ROLE_TYPE AS ENUM ('UNKNOWN', 'ATTACKER', 'DELIVERY' );

CREATE TABLE content_rule (
  id              SERIAL PRIMARY KEY,
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  path            VARCHAR(2048) NOT NULL,
  path_matching   MATCHING_TYPE,
  body            VARCHAR(2048),
  body_matching   MATCHING_TYPE,
  method          METHOD_TYPE,
  content_id      INT NOT NULL,
  port            INT NOT NULL DEFAULT 0,
  app_id          INT DEFAULT 0,
  CONSTRAINT fk_content_id FOREIGN KEY(content_id) REFERENCES content(id)
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
  content_id      INT,
  rule_id         INT
);

GRANT ALL PRIVILEGES ON content TO lo;
GRANT ALL PRIVILEGES ON content_id_seq TO lo;
GRANT ALL PRIVILEGES ON content_rule TO lo;
GRANT ALL PRIVILEGES ON content_rule_id_seq TO lo;
GRANT ALL PRIVILEGES ON request TO lo;
GRANT ALL PRIVILEGES ON request_id_seq TO lo;
GRANT ALL PRIVILEGES ON app TO lo;
GRANT ALL PRIVILEGES ON app_id_seq TO lo;
GRANT ALL PRIVILEGES ON process_queue TO lo;
GRANT ALL PRIVILEGES ON process_queue_id_seq TO lo;

