
DROP DATABASE IF EXISTS lophiid;
CREATE DATABASE lophiid;

\connect lophiid

CREATE USER lo WITH PASSWORD 'test';


CREATE TABLE content (
  id              SERIAL PRIMARY KEY,
  name            VARCHAR(256) NOT NULL,
  content         TEXT NOT NULL,
  content_type    VARCHAR(256) NOT NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);


CREATE TYPE MATCHING_TYPE AS ENUM ('exact', 'prefix', 'suffix', 'contains', 'regex');
CREATE TYPE METHOD_TYPE AS ENUM ('GET', 'POST', 'HEAD', 'TRACE', 'OPTIONS', 'DELETE', 'PUT', 'ANY');

CREATE TABLE content_rule (
  id              SERIAL PRIMARY KEY,
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  path            VARCHAR(2048) NOT NULL,
  path_matching   MATCHING_TYPE,
  body            VARCHAR(2048),
  body_matching   MATCHING_TYPE,
  method          METHOD_TYPE,
  content_id      INT,
  CONSTRAINT fk_content_id FOREIGN KEY(content_id) REFERENCES content(id)
);


GRANT ALL PRIVILEGES ON content TO lo;
GRANT ALL PRIVILEGES ON content_id_seq TO lo;
GRANT ALL PRIVILEGES ON content_rule TO lo;
GRANT ALL PRIVILEGES ON content_rule_id_seq TO lo;
