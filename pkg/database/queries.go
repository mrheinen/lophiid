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
