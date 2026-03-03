// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
package database

// Count the total of requests per month. This is very slow.
const QueryTotalRequestsPerMonthLastYear = `
SELECT
    TO_CHAR(DATE_TRUNC('month', created_at), 'YYYY-MM') AS month,
    COUNT(*) as total_entries
FROM request
WHERE created_at > NOW() - INTERVAL '12 months'
GROUP BY month
ORDER BY month DESC;
`

const QueryTotalRequestsPerDayLast7Days = `
SELECT
    TO_CHAR(DATE_TRUNC('day', created_at), 'MM-DD') AS day,
    COUNT(*) as total_entries
FROM request
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY day
ORDER BY day DESC;
`

const QueryTotalNewDownloadsPerDayLast7Days = `
SELECT
    TO_CHAR(DATE_TRUNC('day', created_at), 'MM-DD') AS day,
    COUNT(*) as total_entries
FROM downloads
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY day
ORDER BY day DESC;
`

const QueryTotalRequestsPerDayPerMethodLast7Days = `
SELECT
    TO_CHAR(DATE_TRUNC('day', created_at), 'MM-DD') AS day,
    COUNT(method) as total_entries, method
FROM request
WHERE created_at >= NOW() - INTERVAL '7 days'
GROUP BY day, method
ORDER BY day DESC;
`

const QueryCountMethodsLast24Hours = `
SELECT
    COUNT(method) as total_entries, method
FROM request
WHERE created_at >= NOW() - INTERVAL '24 hours'
    AND created_at < NOW()
GROUP BY  method
ORDER BY total_entries DESC;
`

const QueryCountMalwareHosted24Hours = `
SELECT
    COUNT(*) as total_entries, type, subtype
FROM ip_event
WHERE created_at >= NOW() - INTERVAL '24 hours'
    AND created_at < NOW() AND type = 'HOSTED_MALWARE'
GROUP BY  type, subtype
ORDER BY total_entries DESC;
`

const QueryTop10SourcesLastDay = `
SELECT
    source_ip, COUNT(*) AS total_requests
FROM public.request
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY source_ip
ORDER BY total_requests DESC
LIMIT 10;
`

const QueryTop10URILastDay = `
SELECT
    uri, COUNT(*) AS total_requests
FROM public.request
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY uri
ORDER BY total_requests DESC
LIMIT 10;
`

const QueryTop10URIsCodeExecutionLastDay = `
SELECT
    uri, COUNT(*) AS total_requests
FROM public.request
WHERE triage_payload_type = 'CODE_EXECUTION'
    AND created_at >= NOW() - INTERVAL '24 hours'
GROUP BY uri
ORDER BY total_requests DESC
LIMIT 10;
`

const QueryTop10URIsShellCommandLastDay = `
SELECT
    uri, COUNT(*) AS total_requests
FROM public.request
WHERE triage_payload_type = 'SHELL_COMMAND'
    AND created_at >= NOW() - INTERVAL '24 hours'
GROUP BY uri
ORDER BY total_requests DESC
LIMIT 10;
`

const QueryTriagePayloadTypeCounts = `
SELECT
    triage_payload_type, COUNT(*) AS total_requests
FROM public.request
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY triage_payload_type
ORDER BY total_requests DESC;
`

// QueryURIStatsSummaryTemplate returns first_seen, last_seen, first_requester_ip and total_requests
// for a given column value. The %s placeholder must be replaced with a validated column name
// (uri, cmp_hash, or base_hash) before use.
const QueryURIStatsSummaryTemplate = `
SELECT
    MIN(created_at) AS first_seen,
    MAX(created_at) AS last_seen,
    (SELECT source_ip FROM public.request WHERE %s = $1%s ORDER BY created_at ASC LIMIT 1) AS first_requester_ip,
    COUNT(*) AS total_requests
FROM public.request
WHERE %s = $1%s;
`

// QueryURIStatsPerMonthTemplate returns per-month request counts for a given column value.
// The %s placeholder must be replaced with a validated column name before use.
const QueryURIStatsPerMonthTemplate = `
SELECT
    TO_CHAR(DATE_TRUNC('month', created_at), 'YYYY-MM') AS month,
    COUNT(*) AS total_entries
FROM public.request
WHERE %s = $1%s
GROUP BY month
ORDER BY month ASC;
`
