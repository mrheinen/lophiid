
DROP DATABASE IF EXISTS lophiid;
CREATE DATABASE lophiid;

\connect lophiid

CREATE USER lo WITH PASSWORD 'test';


CREATE TABLE content (
  id              SERIAL PRIMARY KEY,
  name            VARCHAR(256) NOT NULL,
  content         TEXT NOT NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE content_location (
  id              SERIAL PRIMARY KEY,
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  location        VARCHAR(2048) NOT NULL,
  content_id      INT,
  CONSTRAINT fk_content_id FOREIGN KEY(content_id) REFERENCES content(id)
);

GRANT ALL PRIVILEGES ON content TO lo;
GRANT ALL PRIVILEGES ON content_id_seq TO lo;
GRANT ALL PRIVILEGES ON content_location_id_seq TO lo;
