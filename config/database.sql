--
-- PostgreSQL database dump
--

\restrict b26dYyrIMRZ1SdWhQqet7cFWR7vpxt3JTY0hcpVouVT9V5gmBgkA8G2821V8zri

-- Dumped from database version 15.14 (Debian 15.14-0+deb12u1)
-- Dumped by pg_dump version 15.14 (Debian 15.14-0+deb12u1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_stat_statements; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA public;


--
-- Name: EXTENSION pg_stat_statements; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION pg_stat_statements IS 'track planning and execution statistics of all SQL statements executed';


--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: download_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.download_status AS ENUM (
    'UNKNOWN',
    'SCHEDULED',
    'DONE'
);


ALTER TYPE public.download_status OWNER TO postgres;

--
-- Name: ioc_source_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.ioc_source_type AS ENUM (
    'UNKNOWN',
    'ABUSE'
);


ALTER TYPE public.ioc_source_type OWNER TO postgres;

--
-- Name: ip_event_ref_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.ip_event_ref_type AS ENUM (
    'UNKNOWN',
    'REQUEST_ID',
    'RULE_ID',
    'CONTENT_ID',
    'VT_ANALYSIS_ID',
    'REQUEST_SOURCE_IP',
    'SESSION_ID',
    'APP_ID',
    'NONE',
    'DOWNLOAD_ID',
    'REQUEST_DESCRIPTION_ID'
);


ALTER TYPE public.ip_event_ref_type OWNER TO postgres;

--
-- Name: ip_event_source; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.ip_event_source AS ENUM (
    'OTHER',
    'VT',
    'RULE',
    'BACKEND',
    'ANALYSIS',
    'WHOIS',
    'AI',
    'AGENT'
);


ALTER TYPE public.ip_event_source OWNER TO postgres;

--
-- Name: ip_event_sub_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.ip_event_sub_type AS ENUM (
    'UNKNOWN',
    'MALWARE_NEW',
    'MALWARE_OLD',
    'SENT_NEW_MALWARE',
    'NONE',
    'RATE_WINDOW',
    'RATE_BUCKET',
    'TC_SCANNED',
    'TC_ATTACKED',
    'TC_RECONNED',
    'TC_BRUTEFORCED',
    'TC_CRAWLED',
    'CRAWLED',
    'ATTACKED',
    'RECONNED',
    'SCANNED',
    'BRUTEFORCED',
    'TC_MALICIOUS',
    'IP_RATE_WINDOW',
    'URI_RATE_WINDOW',
    'URI_RATE_BUCKET',
    'IP_RATE_BUCKET',
    'SUCCESS',
    'FAILURE'
);


ALTER TYPE public.ip_event_sub_type OWNER TO postgres;

--
-- Name: ip_event_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.ip_event_type AS ENUM (
    'UNKNOWN',
    'ATTACKED',
    'RECONNED',
    'CRAWLED',
    'SCANNED',
    'BRUTEFORCED',
    'HOSTED_MALWARE',
    'HOST_C2',
    'RATELIMITED',
    'HOSTED_NEW_MALWARE',
    'SENT_MALWARE',
    'SENT_NEW_MALWARE',
    'TRAFFIC_CLASS',
    'PING'
);


ALTER TYPE public.ip_event_type OWNER TO postgres;

--
-- Name: ip_role_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.ip_role_type AS ENUM (
    'UNKNOWN',
    'ATTACK_SOURCE',
    'PAYLOAD_SERVER',
    'CONTROL_SERVER'
);


ALTER TYPE public.ip_role_type OWNER TO postgres;

--
-- Name: matching_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.matching_type AS ENUM (
    'exact',
    'prefix',
    'suffix',
    'contains',
    'regex',
    'none'
);


ALTER TYPE public.matching_type OWNER TO postgres;

--
-- Name: metadata_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.metadata_type AS ENUM (
    'PAYLOAD_LINK',
    'DECODED_STRING_BASE64',
    'SCRIPT_RESPONSE_BODY',
    'PAYLOAD_TCP_LINK',
    'PAYLOAD_NETCAT',
    'DECODED_UNICODE_STRING',
    'DECODED_STRING_UNICODE',
    'PAYLOAD_PING'
);


ALTER TYPE public.metadata_type OWNER TO postgres;

--
-- Name: method_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.method_type AS ENUM (
    'GET',
    'POST',
    'HEAD',
    'TRACE',
    'OPTIONS',
    'DELETE',
    'PUT',
    'ANY'
);


ALTER TYPE public.method_type OWNER TO postgres;

--
-- Name: payload_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.payload_type AS ENUM (
    'UNKNOWN',
    'SHELL_COMMAND',
    'FILE_ACCESS',
    'CODE_EXECUTION',
    'SQL_INJECTION'
);


ALTER TYPE public.payload_type OWNER TO postgres;

--
-- Name: request_purpose; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.request_purpose AS ENUM (
    'UNKNOWN',
    'RECON',
    'CRAWL',
    'ATTACK'
);


ALTER TYPE public.request_purpose OWNER TO postgres;

--
-- Name: responder_decoder_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.responder_decoder_type AS ENUM (
    'NONE',
    'URI',
    'HTML'
);


ALTER TYPE public.responder_decoder_type OWNER TO postgres;

--
-- Name: responder_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.responder_type AS ENUM (
    'UNKNOWN',
    'COMMAND_INJECTION',
    'NONE',
    'SOURCE_CODE_INJECTION',
    'AUTO'
);


ALTER TYPE public.responder_type OWNER TO postgres;

--
-- Name: review_status_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.review_status_type AS ENUM (
    'UNREVIEWED',
    'REVIEWED_OK',
    'REVIEWED_NOK'
);


ALTER TYPE public.review_status_type OWNER TO postgres;

--
-- Name: status_code; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.status_code AS ENUM (
    '200',
    '301',
    '302',
    '400',
    '401',
    '403',
    '404',
    '500',
    '201',
    '202',
    '203',
    '204',
    '206',
    '300',
    '303',
    '304',
    '307',
    '402',
    '405',
    '406',
    '408',
    '409',
    '410',
    '413',
    '414',
    '415',
    '416',
    '418',
    '429',
    '501',
    '502',
    '503',
    '504',
    '505'
);


ALTER TYPE public.status_code OWNER TO postgres;

--
-- Name: triage_status_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.triage_status_type AS ENUM (
    'UNKNOWN',
    'PENDING',
    'DONE',
    'FAILED'
);


ALTER TYPE public.triage_status_type OWNER TO postgres;

--
-- Name: yara_status_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.yara_status_type AS ENUM (
    'UNKNOWN',
    'PENDING',
    'DONE',
    'FAILED'
);


ALTER TYPE public.yara_status_type OWNER TO postgres;

--
-- Name: sync_request_refs(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.sync_request_refs() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO public.request_refs (id, created_at)
    VALUES (NEW.id, NEW.created_at)
    ON CONFLICT (id) DO NOTHING;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.sync_request_refs() OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: app; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.app (
    id integer NOT NULL,
    name character varying(512),
    vendor character varying(512),
    version character varying(512),
    link character varying(2048),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    os character varying(512),
    ext_version integer DEFAULT 1,
    ext_uuid character varying(36) DEFAULT gen_random_uuid(),
    cves character varying(15)[]
);


ALTER TABLE public.app OWNER TO postgres;

--
-- Name: app_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.app_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.app_id_seq OWNER TO postgres;

--
-- Name: app_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.app_id_seq OWNED BY public.app.id;


--
-- Name: content; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.content (
    id integer NOT NULL,
    name character varying(256) NOT NULL,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    content_type character varying(256),
    server character varying(256),
    description text,
    data bytea,
    status_code public.status_code,
    script text,
    headers character varying(4096)[],
    ext_uuid character varying(36) DEFAULT gen_random_uuid() NOT NULL,
    ext_version integer DEFAULT 1,
    rule_uuid character varying(36) DEFAULT ''::character varying
);


ALTER TABLE public.content OWNER TO postgres;

--
-- Name: content_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.content_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.content_id_seq OWNER TO postgres;

--
-- Name: content_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.content_id_seq OWNED BY public.content.id;


--
-- Name: content_location; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.content_location (
    id integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    location character varying(2048) NOT NULL,
    content_id integer
);


ALTER TABLE public.content_location OWNER TO postgres;

--
-- Name: content_location_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.content_location_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.content_location_id_seq OWNER TO postgres;

--
-- Name: content_location_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.content_location_id_seq OWNED BY public.content_location.id;


--
-- Name: content_rule; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.content_rule (
    id integer NOT NULL,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    uri character varying(2048) NOT NULL,
    uri_matching public.matching_type,
    body character varying(2048),
    body_matching public.matching_type,
    method public.method_type,
    content_id integer,
    app_id integer,
    port integer DEFAULT 0 NOT NULL,
    alert boolean DEFAULT false,
    request_purpose public.request_purpose DEFAULT 'UNKNOWN'::public.request_purpose,
    ext_version integer DEFAULT 1,
    ext_uuid character varying(36) DEFAULT gen_random_uuid(),
    app_uuid character varying(36) DEFAULT ''::character varying,
    content_uuid character varying(36) DEFAULT ''::character varying,
    responder public.responder_type DEFAULT 'UNKNOWN'::public.responder_type,
    responder_regex character varying(1024) DEFAULT ''::character varying,
    responder_decoder public.responder_decoder_type DEFAULT 'NONE'::public.responder_decoder_type,
    enabled boolean DEFAULT true,
    ports integer[] DEFAULT '{}'::integer[],
    block boolean DEFAULT false
);


ALTER TABLE public.content_rule OWNER TO postgres;

--
-- Name: content_rule_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.content_rule_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.content_rule_id_seq OWNER TO postgres;

--
-- Name: content_rule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.content_rule_id_seq OWNED BY public.content_rule.id;


--
-- Name: downloads; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.downloads (
    id integer NOT NULL,
    original_url character varying(2048),
    used_url character varying(2048),
    ip character varying(52),
    host character varying(1024),
    content_type character varying(256),
    file_location character varying(512),
    size integer,
    port integer,
    request_id integer,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    last_seen_at timestamp without time zone DEFAULT now() NOT NULL,
    sha256sum character varying(64),
    times_seen integer DEFAULT 1 NOT NULL,
    last_request_id integer,
    vt_url_analysis_id character varying(1024) DEFAULT ''::character varying,
    vt_analysis_harmless integer DEFAULT 0,
    vt_analysis_malicious integer DEFAULT 0,
    vt_analysis_suspicious integer DEFAULT 0,
    vt_analysis_undetected integer DEFAULT 0,
    vt_analysis_timeout integer DEFAULT 0,
    vt_file_analysis_id character varying(1024) DEFAULT ''::character varying,
    vt_file_analysis_submitted boolean DEFAULT false,
    vt_file_analysis_done boolean DEFAULT false,
    vt_file_analysis_result character varying(1024)[],
    raw_http_response text DEFAULT ''::text,
    honeypot_ip character varying(52) DEFAULT ''::character varying,
    status public.download_status DEFAULT 'UNKNOWN'::public.download_status,
    content_type_detected character varying(256) DEFAULT ''::character varying,
    detected_content_type character varying(256) DEFAULT ''::character varying,
    yara_status public.yara_status_type DEFAULT 'UNKNOWN'::public.yara_status_type,
    yara_last_scan timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    yara_scanned_unpacked boolean DEFAULT false,
    yara_description text,
    source_download_id integer DEFAULT 0,
    source_ip character varying(52) DEFAULT ''::character varying
);


ALTER TABLE public.downloads OWNER TO postgres;

--
-- Name: downloads_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.downloads_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.downloads_id_seq OWNER TO postgres;

--
-- Name: downloads_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.downloads_id_seq OWNED BY public.downloads.id;


--
-- Name: honeypot; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.honeypot (
    id integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    ip character varying(52),
    last_checkin timestamp without time zone DEFAULT now() NOT NULL,
    default_content_id integer DEFAULT 1 NOT NULL,
    auth_token character varying(64) DEFAULT ''::character varying,
    version character varying(64) DEFAULT ''::character varying NOT NULL,
    ports integer[],
    ssl_ports integer[]
);


ALTER TABLE public.honeypot OWNER TO postgres;

--
-- Name: honeypot_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.honeypot_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.honeypot_id_seq OWNER TO postgres;

--
-- Name: honeypot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.honeypot_id_seq OWNED BY public.honeypot.id;


--
-- Name: ioc; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ioc (
    id integer NOT NULL,
    source public.ioc_source_type DEFAULT 'UNKNOWN'::public.ioc_source_type,
    threadtype character varying(128),
    threadtypedescription character varying(8192),
    ioctype character varying(128),
    ioctypedescription character varying(8192),
    malware character varying(128),
    malwareprintable character varying(128),
    malpediaurl character varying(2048),
    abuseconfidencelevel integer DEFAULT 0,
    abuseid character varying(64),
    abusereporter character varying(512)
);


ALTER TABLE public.ioc OWNER TO postgres;

--
-- Name: ioc_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.ioc_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.ioc_id_seq OWNER TO postgres;

--
-- Name: ioc_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.ioc_id_seq OWNED BY public.ioc.id;


--
-- Name: ip_event; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ip_event (
    id integer NOT NULL,
    ip character varying(52),
    domain character varying(256),
    details character varying(4096),
    note character varying(4096),
    type public.ip_event_type DEFAULT 'UNKNOWN'::public.ip_event_type,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    count integer DEFAULT 0,
    request_id integer,
    source_ref character varying(512),
    source public.ip_event_source DEFAULT 'OTHER'::public.ip_event_source,
    honeypot_ip character varying(52) DEFAULT ''::character varying,
    first_seen_at timestamp without time zone DEFAULT timezone('utc'::text, now()),
    subtype public.ip_event_sub_type DEFAULT 'NONE'::public.ip_event_sub_type,
    source_ref_type public.ip_event_ref_type DEFAULT 'NONE'::public.ip_event_ref_type
);


ALTER TABLE public.ip_event OWNER TO postgres;

--
-- Name: ip_event_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.ip_event_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.ip_event_id_seq OWNER TO postgres;

--
-- Name: ip_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.ip_event_id_seq OWNED BY public.ip_event.id;


--
-- Name: llm_code_execution; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.llm_code_execution (
    id integer NOT NULL,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    output bytea DEFAULT '\x'::bytea NOT NULL,
    language character varying(128),
    headers text,
    request_id integer,
    session_id integer,
    source_model character varying(256) DEFAULT 'UNKNOWN'::character varying,
    stdout bytea DEFAULT '\x'::bytea NOT NULL,
    snippet bytea DEFAULT '\x'::bytea NOT NULL
);


ALTER TABLE public.llm_code_execution OWNER TO postgres;

--
-- Name: llm_code_execution_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.llm_code_execution_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.llm_code_execution_id_seq OWNER TO postgres;

--
-- Name: llm_code_execution_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.llm_code_execution_id_seq OWNED BY public.llm_code_execution.id;


--
-- Name: p0f_result; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.p0f_result (
    id integer NOT NULL,
    ip character varying(52),
    first_seen_time timestamp without time zone,
    last_seen_time timestamp without time zone,
    total_count integer DEFAULT 0,
    uptime_minutes integer DEFAULT 0,
    uptime_days integer DEFAULT 0,
    distance integer DEFAULT 0,
    last_nat_detection_time timestamp without time zone,
    last_os_change_time timestamp without time zone,
    os_match_quality integer DEFAULT 0,
    os_name character varying(32),
    os_version character varying(32),
    http_name character varying(32),
    http_flavor character varying(32),
    language character varying(32),
    link_type character varying(32),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.p0f_result OWNER TO postgres;

--
-- Name: p0f_result_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.p0f_result_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.p0f_result_id_seq OWNER TO postgres;

--
-- Name: p0f_result_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.p0f_result_id_seq OWNED BY public.p0f_result.id;


--
-- Name: request; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.request (
    id integer NOT NULL,
    proto character varying(10),
    host character varying(2048),
    port integer,
    method character varying(10),
    uri character varying(2048),
    query character varying(2048),
    path character varying(2048),
    referer character varying(2048),
    content_type character varying(1024),
    content_length integer,
    user_agent character varying(2048),
    body bytea DEFAULT '\x'::bytea NOT NULL,
    headers character varying(16000)[],
    source_ip character varying(512),
    source_port integer,
    raw bytea,
    raw_response text,
    time_received timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    honeypot_ip character varying(40),
    starred boolean DEFAULT false,
    content_dynamic boolean DEFAULT false,
    has_malware boolean DEFAULT false,
    base_hash character varying(64) DEFAULT ''::character varying,
    cmp_hash character varying(64) DEFAULT ''::character varying,
    content_id integer,
    session_id integer DEFAULT 0 NOT NULL,
    app_id integer DEFAULT 0 NOT NULL,
    rule_id integer DEFAULT 0 NOT NULL,
    rule_uuid character varying(36) DEFAULT ''::character varying,
    triage_payload text,
    triage_payload_type public.payload_type DEFAULT 'UNKNOWN'::public.payload_type,
    triage_has_payload boolean DEFAULT false
)
PARTITION BY RANGE (created_at);


ALTER TABLE public.request OWNER TO postgres;

--
-- Name: request_description; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.request_description (
    id integer NOT NULL,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    cmp_hash character varying(64) DEFAULT ''::character varying,
    example_request_id integer,
    ai_description text,
    ai_application character varying(128),
    ai_vulnerability_type character varying(128),
    ai_malicious character varying(12),
    ai_cve character varying(64),
    review_status public.review_status_type DEFAULT 'UNREVIEWED'::public.review_status_type,
    source_model character varying(256) DEFAULT 'UNKNOWN'::character varying,
    triage_status public.triage_status_type DEFAULT 'UNKNOWN'::public.triage_status_type,
    ai_has_payload character varying(6) DEFAULT ''::character varying,
    ai_targeted_parameter character varying(256) DEFAULT ''::character varying,
    ai_shell_commands character varying(10000) DEFAULT ''::character varying,
    ai_mitre_attack character varying(2048) DEFAULT ''::character varying
);


ALTER TABLE public.request_description OWNER TO postgres;

--
-- Name: request_description_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.request_description_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.request_description_id_seq OWNER TO postgres;

--
-- Name: request_description_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.request_description_id_seq OWNED BY public.request_description.id;


--
-- Name: request_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.request_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.request_id_seq OWNER TO postgres;

--
-- Name: request_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.request_id_seq OWNED BY public.request.id;


--



--
-- Name: request_metadata; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.request_metadata (
    id integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    request_id integer,
    type public.metadata_type NOT NULL,
    data text
);


ALTER TABLE public.request_metadata OWNER TO postgres;

--
-- Name: request_metadata_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.request_metadata_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.request_metadata_id_seq OWNER TO postgres;

--
-- Name: request_metadata_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.request_metadata_id_seq OWNED BY public.request_metadata.id;


--
-- Name: request_refs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.request_refs (
    id integer DEFAULT nextval('public.request_id_seq'::regclass) NOT NULL,
    created_at timestamp without time zone NOT NULL
);


ALTER TABLE public.request_refs OWNER TO postgres;

--
-- Name: rule_tag_per_request; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.rule_tag_per_request (
    id integer NOT NULL,
    tag_id integer,
    request_id integer,
    tag_per_rule_id integer,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);


ALTER TABLE public.rule_tag_per_request OWNER TO postgres;

--
-- Name: rule_tag_per_request_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.rule_tag_per_request_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.rule_tag_per_request_id_seq OWNER TO postgres;

--
-- Name: rule_tag_per_request_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.rule_tag_per_request_id_seq OWNED BY public.rule_tag_per_request.id;


--
-- Name: session; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.session (
    id integer NOT NULL,
    active boolean DEFAULT false,
    ip character varying(52) NOT NULL,
    started_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    ended_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);


ALTER TABLE public.session OWNER TO postgres;

--
-- Name: session_execution_context; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.session_execution_context (
    id integer NOT NULL,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    env_hostname character varying(256),
    env_cwd character varying(1024),
    env_user character varying(128),
    input character varying(4096),
    output character varying(16384),
    summary character varying(8192),
    request_id integer,
    session_id integer,
    source_model character varying(256) DEFAULT 'UNKNOWN'::character varying
);


ALTER TABLE public.session_execution_context OWNER TO postgres;

--
-- Name: session_execution_context_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.session_execution_context_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.session_execution_context_id_seq OWNER TO postgres;

--
-- Name: session_execution_context_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.session_execution_context_id_seq OWNED BY public.session_execution_context.id;


--
-- Name: session_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.session_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.session_id_seq OWNER TO postgres;

--
-- Name: session_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.session_id_seq OWNED BY public.session.id;


--
-- Name: stored_query; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.stored_query (
    id integer NOT NULL,
    query character varying(8192),
    description text,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    record_count integer DEFAULT 0,
    times_run integer DEFAULT 0,
    last_ran_at timestamp without time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.stored_query OWNER TO postgres;

--
-- Name: stored_query_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.stored_query_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.stored_query_id_seq OWNER TO postgres;

--
-- Name: stored_query_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.stored_query_id_seq OWNED BY public.stored_query.id;


--
-- Name: tag; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tag (
    id integer NOT NULL,
    name character varying(64) NOT NULL,
    color_html character varying(8),
    description text,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.tag OWNER TO postgres;

--
-- Name: tag_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tag_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tag_id_seq OWNER TO postgres;

--
-- Name: tag_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tag_id_seq OWNED BY public.tag.id;


--
-- Name: tag_per_query; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tag_per_query (
    id integer NOT NULL,
    tag_id integer,
    query_id integer
);


ALTER TABLE public.tag_per_query OWNER TO postgres;

--
-- Name: tag_per_query_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tag_per_query_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tag_per_query_id_seq OWNER TO postgres;

--
-- Name: tag_per_query_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tag_per_query_id_seq OWNED BY public.tag_per_query.id;


--
-- Name: tag_per_request; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tag_per_request (
    id integer NOT NULL,
    tag_id integer,
    request_id integer,
    tag_per_query_id integer,
    tag_per_rule_id integer
);


ALTER TABLE public.tag_per_request OWNER TO postgres;

--
-- Name: tag_per_request_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tag_per_request_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tag_per_request_id_seq OWNER TO postgres;

--
-- Name: tag_per_request_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tag_per_request_id_seq OWNED BY public.tag_per_request.id;


--
-- Name: tag_per_rule; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tag_per_rule (
    id integer NOT NULL,
    rule_id integer,
    tag_id integer,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);


ALTER TABLE public.tag_per_rule OWNER TO postgres;

--
-- Name: tag_per_rule_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.tag_per_rule_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tag_per_rule_id_seq OWNER TO postgres;

--
-- Name: tag_per_rule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.tag_per_rule_id_seq OWNED BY public.tag_per_rule.id;


--
-- Name: vt_ipresult; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vt_ipresult (
    id integer NOT NULL,
    ip character varying(52),
    whois text,
    country character varying(64),
    asn integer DEFAULT 0,
    as_owner character varying(512),
    last_analysis_date timestamp without time zone NOT NULL,
    result_harmless integer DEFAULT 0,
    result_malicious integer DEFAULT 0,
    result_suspicious integer DEFAULT 0,
    result_undetected integer DEFAULT 0,
    result_timeout integer DEFAULT 0,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.vt_ipresult OWNER TO postgres;

--
-- Name: vt_ipresult_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.vt_ipresult_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.vt_ipresult_id_seq OWNER TO postgres;

--
-- Name: vt_ipresult_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.vt_ipresult_id_seq OWNED BY public.vt_ipresult.id;


--
-- Name: whois; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.whois (
    id integer NOT NULL,
    data text,
    ip character varying(52),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    country character varying(128) DEFAULT ''::character varying,
    rdap bytea DEFAULT '\x'::bytea NOT NULL
);


ALTER TABLE public.whois OWNER TO postgres;

--
-- Name: whois_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.whois_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.whois_id_seq OWNER TO postgres;

--
-- Name: whois_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.whois_id_seq OWNED BY public.whois.id;


--
-- Name: yara; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.yara (
    id integer NOT NULL,
    download_id integer,
    identifier character varying(2048),
    author character varying(2048),
    metadata character varying(4096)[],
    tags character varying(512)[],
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    description character varying(4096),
    malpedia_reference character varying(2048),
    malpedia_version character varying(64),
    malpedia_license character varying(256),
    malpedia_sharing character varying(32),
    reference character varying(2048),
    date character varying(64),
    eid character varying(256)
);


ALTER TABLE public.yara OWNER TO postgres;

--
-- Name: yara_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.yara_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.yara_id_seq OWNER TO postgres;

--
-- Name: yara_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.yara_id_seq OWNED BY public.yara.id;


--
-- Name: app id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.app ALTER COLUMN id SET DEFAULT nextval('public.app_id_seq'::regclass);


--
-- Name: content id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.content ALTER COLUMN id SET DEFAULT nextval('public.content_id_seq'::regclass);


--
-- Name: content_location id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.content_location ALTER COLUMN id SET DEFAULT nextval('public.content_location_id_seq'::regclass);


--
-- Name: content_rule id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.content_rule ALTER COLUMN id SET DEFAULT nextval('public.content_rule_id_seq'::regclass);


--
-- Name: downloads id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.downloads ALTER COLUMN id SET DEFAULT nextval('public.downloads_id_seq'::regclass);


--
-- Name: honeypot id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.honeypot ALTER COLUMN id SET DEFAULT nextval('public.honeypot_id_seq'::regclass);


--
-- Name: ioc id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ioc ALTER COLUMN id SET DEFAULT nextval('public.ioc_id_seq'::regclass);


--
-- Name: ip_event id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ip_event ALTER COLUMN id SET DEFAULT nextval('public.ip_event_id_seq'::regclass);


--
-- Name: llm_code_execution id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.llm_code_execution ALTER COLUMN id SET DEFAULT nextval('public.llm_code_execution_id_seq'::regclass);


--
-- Name: p0f_result id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.p0f_result ALTER COLUMN id SET DEFAULT nextval('public.p0f_result_id_seq'::regclass);


--
-- Name: request id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.request ALTER COLUMN id SET DEFAULT nextval('public.request_id_seq'::regclass);


--
-- Name: request_description id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.request_description ALTER COLUMN id SET DEFAULT nextval('public.request_description_id_seq'::regclass);


--
-- Name: request_metadata id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.request_metadata ALTER COLUMN id SET DEFAULT nextval('public.request_metadata_id_seq'::regclass);


--
-- Name: rule_tag_per_request id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.rule_tag_per_request ALTER COLUMN id SET DEFAULT nextval('public.rule_tag_per_request_id_seq'::regclass);


--
-- Name: session id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.session ALTER COLUMN id SET DEFAULT nextval('public.session_id_seq'::regclass);


--
-- Name: session_execution_context id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.session_execution_context ALTER COLUMN id SET DEFAULT nextval('public.session_execution_context_id_seq'::regclass);


--
-- Name: stored_query id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.stored_query ALTER COLUMN id SET DEFAULT nextval('public.stored_query_id_seq'::regclass);


--
-- Name: tag id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag ALTER COLUMN id SET DEFAULT nextval('public.tag_id_seq'::regclass);


--
-- Name: tag_per_query id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_query ALTER COLUMN id SET DEFAULT nextval('public.tag_per_query_id_seq'::regclass);


--
-- Name: tag_per_request id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_request ALTER COLUMN id SET DEFAULT nextval('public.tag_per_request_id_seq'::regclass);


--
-- Name: tag_per_rule id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_rule ALTER COLUMN id SET DEFAULT nextval('public.tag_per_rule_id_seq'::regclass);


--
-- Name: vt_ipresult id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vt_ipresult ALTER COLUMN id SET DEFAULT nextval('public.vt_ipresult_id_seq'::regclass);


--
-- Name: whois id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.whois ALTER COLUMN id SET DEFAULT nextval('public.whois_id_seq'::regclass);


--
-- Name: yara id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.yara ALTER COLUMN id SET DEFAULT nextval('public.yara_id_seq'::regclass);


--
-- Name: app app_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.app
    ADD CONSTRAINT app_pkey PRIMARY KEY (id);


--
-- Name: content_location content_location_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.content_location
    ADD CONSTRAINT content_location_pkey PRIMARY KEY (id);


--
-- Name: content content_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.content
    ADD CONSTRAINT content_pkey PRIMARY KEY (id);


--
-- Name: content_rule content_rule_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.content_rule
    ADD CONSTRAINT content_rule_pkey PRIMARY KEY (id);


--
-- Name: downloads downloads_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.downloads
    ADD CONSTRAINT downloads_pkey PRIMARY KEY (id);


--
-- Name: honeypot honeypot_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.honeypot
    ADD CONSTRAINT honeypot_pkey PRIMARY KEY (id);


--
-- Name: ioc ioc_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ioc
    ADD CONSTRAINT ioc_pkey PRIMARY KEY (id);


--
-- Name: ip_event ip_event_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ip_event
    ADD CONSTRAINT ip_event_pkey PRIMARY KEY (id);


--
-- Name: llm_code_execution llm_code_execution_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.llm_code_execution
    ADD CONSTRAINT llm_code_execution_pkey PRIMARY KEY (id);


--
-- Name: p0f_result p0f_result_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.p0f_result
    ADD CONSTRAINT p0f_result_pkey PRIMARY KEY (id);


--
-- Name: request_description request_description_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.request_description
    ADD CONSTRAINT request_description_pkey PRIMARY KEY (id);


--
-- Name: request request_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.request
    ADD CONSTRAINT request_pkey PRIMARY KEY (id, created_at);


--


--
-- Name: request_metadata request_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.request_metadata
    ADD CONSTRAINT request_metadata_pkey PRIMARY KEY (id);


--
-- Name: request_refs request_refs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.request_refs
    ADD CONSTRAINT request_refs_pkey PRIMARY KEY (id);


--
-- Name: session_execution_context session_execution_context_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.session_execution_context
    ADD CONSTRAINT session_execution_context_pkey PRIMARY KEY (id);


--
-- Name: session session_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.session
    ADD CONSTRAINT session_pkey PRIMARY KEY (id);


--
-- Name: stored_query stored_query_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.stored_query
    ADD CONSTRAINT stored_query_pkey PRIMARY KEY (id);


--
-- Name: tag_per_query tag_per_query_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_query
    ADD CONSTRAINT tag_per_query_pkey PRIMARY KEY (id);


--
-- Name: tag_per_rule tag_per_rule_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_rule
    ADD CONSTRAINT tag_per_rule_pkey PRIMARY KEY (id);


--
-- Name: tag tag_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag
    ADD CONSTRAINT tag_pkey PRIMARY KEY (id);


--
-- Name: vt_ipresult vt_ipresult_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vt_ipresult
    ADD CONSTRAINT vt_ipresult_pkey PRIMARY KEY (id);


--
-- Name: whois whois_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.whois
    ADD CONSTRAINT whois_pkey PRIMARY KEY (id);


--
-- Name: yara yara_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.yara
    ADD CONSTRAINT yara_pkey PRIMARY KEY (id);


--
-- Name: ip_per_p0f_result; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ip_per_p0f_result ON public.p0f_result USING btree (ip);


--
-- Name: ip_per_whois_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ip_per_whois_idx ON public.whois USING btree (ip);


--
-- Name: request_description_status_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX request_description_status_idx ON public.request_description USING btree (created_at DESC, triage_status);


--
-- Name: requests_has_payload_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_has_payload_idx ON public.request USING btree (triage_has_payload);


--


--
-- Name: requests_starred_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_starred_idx ON public.request USING btree (starred);


--


--
-- Name: requests_base_hash_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_base_hash_idx ON public.request USING btree (time_received DESC, base_hash);


--


--
-- Name: requests_cmp_hash_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_cmp_hash_idx ON public.request USING btree (time_received DESC, cmp_hash);


--


--
-- Name: requests_content_length_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_content_length_idx ON public.request USING btree (time_received DESC, content_length);


--


--
-- Name: requests_created_at_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_created_at_idx ON public.request USING btree (time_received DESC, created_at DESC);


--


--
-- Name: requests_honeypot_ip_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_honeypot_ip_idx ON public.request USING btree (time_received DESC, honeypot_ip);


--


--
-- Name: requests_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_idx ON public.request USING btree (time_received DESC);


--


--
-- Name: requests_port_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_port_idx ON public.request USING btree (time_received DESC, port);


--


--
-- Name: requests_cmp_ruleuuid_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_cmp_ruleuuid_idx ON public.request USING btree (time_received DESC, rule_uuid);


--


--
-- Name: requests_session_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_session_idx ON public.request USING btree (time_received DESC, session_id DESC);


--


--
-- Name: requests_source_ip_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_source_ip_idx ON public.request USING btree (time_received DESC, source_ip DESC);


--


--
-- Name: requests_uri_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX requests_uri_idx ON public.request USING btree (time_received DESC, uri);


--


--
-- Name: request_uri_trgm_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX request_uri_trgm_idx ON public.request USING gin (uri public.gin_trgm_ops);


--


--
-- Name: request_id_per_request_metdata; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX request_id_per_request_metdata ON public.request_metadata USING btree (request_id DESC);


--
-- Name: request_id_tag_per_query_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX request_id_tag_per_query_idx ON public.tag_per_query USING btree (query_id DESC);


--
-- Name: request_id_tag_per_request_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX request_id_tag_per_request_idx ON public.tag_per_request USING btree (request_id DESC);


--
-- Name: request_refs_created_at_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX request_refs_created_at_idx ON public.request_refs USING btree (created_at DESC);

--
-- Name: session_ip; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX session_ip ON public.session USING btree (started_at DESC, active, ip);


--
-- Name: request request_insert_trigger; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER request_insert_trigger AFTER INSERT ON public.request FOR EACH ROW EXECUTE FUNCTION public.sync_request_refs();


--
-- Name: content_location fk_content_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.content_location
    ADD CONSTRAINT fk_content_id FOREIGN KEY (content_id) REFERENCES public.content(id);


--
-- Name: content_rule fk_content_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.content_rule
    ADD CONSTRAINT fk_content_id FOREIGN KEY (content_id) REFERENCES public.content(id);


--
-- Name: yara fk_download_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.yara
    ADD CONSTRAINT fk_download_id FOREIGN KEY (download_id) REFERENCES public.downloads(id) ON DELETE CASCADE;


--
-- Name: request_description fk_example_request_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.request_description
    ADD CONSTRAINT fk_example_request_id FOREIGN KEY (example_request_id) REFERENCES public.request_refs(id);


--
-- Name: llm_code_execution fk_llm_sess_session_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.llm_code_execution
    ADD CONSTRAINT fk_llm_sess_session_id FOREIGN KEY (session_id) REFERENCES public.session(id);


--
-- Name: tag_per_query fk_per_query_stored_query_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_query
    ADD CONSTRAINT fk_per_query_stored_query_id FOREIGN KEY (query_id) REFERENCES public.stored_query(id) ON DELETE CASCADE;


--
-- Name: tag_per_query fk_per_query_tag_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_query
    ADD CONSTRAINT fk_per_query_tag_id FOREIGN KEY (tag_id) REFERENCES public.tag(id) ON DELETE CASCADE;


--
-- Name: tag_per_request fk_per_request_request_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_request
    ADD CONSTRAINT fk_per_request_request_id FOREIGN KEY (request_id) REFERENCES public.request_refs(id) ON DELETE CASCADE;


--
-- Name: tag_per_request fk_per_request_tag_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_request
    ADD CONSTRAINT fk_per_request_tag_id FOREIGN KEY (tag_id) REFERENCES public.tag(id) ON DELETE CASCADE;


--
-- Name: tag_per_rule fk_per_rule_tag_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_rule
    ADD CONSTRAINT fk_per_rule_tag_id FOREIGN KEY (rule_id) REFERENCES public.content_rule(id) ON DELETE CASCADE;


--
-- Name: tag_per_rule fk_per_tag_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_rule
    ADD CONSTRAINT fk_per_tag_id FOREIGN KEY (tag_id) REFERENCES public.tag(id) ON DELETE CASCADE;


--
-- Name: downloads fk_request_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.downloads
    ADD CONSTRAINT fk_request_id FOREIGN KEY (request_id) REFERENCES public.request_refs(id);


--
-- Name: request_metadata fk_request_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.request_metadata
    ADD CONSTRAINT fk_request_id FOREIGN KEY (request_id) REFERENCES public.request_refs(id);


--
-- Name: rule_tag_per_request fk_rule_per_request_request_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.rule_tag_per_request
    ADD CONSTRAINT fk_rule_per_request_request_id FOREIGN KEY (request_id) REFERENCES public.request_refs(id) ON DELETE CASCADE;


--
-- Name: rule_tag_per_request fk_rule_per_request_tag_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.rule_tag_per_request
    ADD CONSTRAINT fk_rule_per_request_tag_id FOREIGN KEY (tag_id) REFERENCES public.tag(id) ON DELETE CASCADE;


--
-- Name: session_execution_context fk_sess_session_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.session_execution_context
    ADD CONSTRAINT fk_sess_session_id FOREIGN KEY (session_id) REFERENCES public.session(id);


--
-- Name: tag_per_request fk_tag_per_query_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_request
    ADD CONSTRAINT fk_tag_per_query_id FOREIGN KEY (tag_per_query_id) REFERENCES public.tag_per_query(id) ON DELETE CASCADE;


--
-- Name: rule_tag_per_request fk_tag_per_rule_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.rule_tag_per_request
    ADD CONSTRAINT fk_tag_per_rule_id FOREIGN KEY (tag_per_rule_id) REFERENCES public.tag_per_rule(id) ON DELETE CASCADE;


--
-- Name: tag_per_request fk_tag_per_rule_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tag_per_request
    ADD CONSTRAINT fk_tag_per_rule_id FOREIGN KEY (tag_per_rule_id) REFERENCES public.tag_per_rule(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict b26dYyrIMRZ1SdWhQqet7cFWR7vpxt3JTY0hcpVouVT9V5gmBgkA8G2821V8zri


-- Default partition for request
CREATE TABLE public.request_default PARTITION OF public.request DEFAULT;
