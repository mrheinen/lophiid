// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
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
package models

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type Download struct {
	ID                      int64                    `ksql:"id,skipInserts" json:"id" doc:"The ID of the download"`
	RequestID               int64                    `ksql:"request_id" json:"request_id" doc:"ID of the request where the download originated from"`
	Size                    int64                    `ksql:"size" json:"size" doc:"Size in bytes of the download"`
	Port                    int64                    `ksql:"port" json:"port" doc:"Server port"`
	CreatedAt               time.Time                `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Date and time of creation"`
	LastSeenAt              time.Time                `ksql:"last_seen_at" json:"last_seen_at" doc:"Date and time of last update"`
	ContentType             string                   `ksql:"content_type" json:"content_type" doc:"The content type (mime) of the download (reported by server)"`
	DetectedContentType     string                   `ksql:"detected_content_type" json:"detected_content_type" doc:"The content type (mime) as detected"`
	OriginalUrl             string                   `ksql:"original_url" json:"original_url" doc:"Original download URL"`
	UsedUrl                 string                   `ksql:"used_url" json:"used_url" doc:"Actually used download URL"`
	IP                      string                   `ksql:"ip" json:"ip" doc:"Download server IP"`
	SourceIP                string                   `ksql:"source_ip" json:"source_ip" doc:"IP of the client that made the request"`
	HoneypotIP              string                   `ksql:"honeypot_ip" json:"honeypot_ip" doc:"Honeypot IP used for download"`
	SHA256sum               string                   `ksql:"sha256sum" json:"sha256sum" doc:"SHA256 sum of the download"`
	Host                    string                   `ksql:"host" json:"host" doc:"The Host header value used in downloading"`
	FileLocation            string                   `ksql:"file_location" json:"file_location" doc:"The file location of the download"`
	TimesSeen               int64                    `ksql:"times_seen" json:"times_seen" doc:"How often this was seen"`
	LastRequestID           int64                    `ksql:"last_request_id" json:"last_request_id" doc:"The request ID of the last request with this download"`
	RawHttpResponse         string                   `ksql:"raw_http_response" json:"raw_http_response" doc:"The HTTP response of the download server"`
	VTURLAnalysisID         string                   `ksql:"vt_url_analysis_id" json:"vt_url_analysis_id" doc:"The virus total URL analysis ID"`
	VTFileAnalysisID        string                   `ksql:"vt_file_analysis_id" json:"vt_file_analysis_id" doc:"The virus total file analysis ID"`
	VTFileAnalysisSubmitted bool                     `ksql:"vt_file_analysis_submitted" json:"vt_file_analysis_submitted"`
	VTFileAnalysisDone      bool                     `ksql:"vt_file_analysis_done" json:"vt_file_analysis_done"`
	VTFileAnalysisResult    pgtype.FlatArray[string] `ksql:"vt_file_analysis_result" json:"vt_file_analysis_result"`
	VTAnalysisHarmless      int64                    `ksql:"vt_analysis_harmless" json:"vt_analysis_harmless" doc:"Virus total results marked harmless"`
	VTAnalysisMalicious     int64                    `ksql:"vt_analysis_malicious" json:"vt_analysis_malicious" doc:"Virus total results marked malicious"`
	VTAnalysisSuspicious    int64                    `ksql:"vt_analysis_suspicious" json:"vt_analysis_suspicious" doc:"Virus total results marked suspicious"`
	VTAnalysisUndetected    int64                    `ksql:"vt_analysis_undetected" json:"vt_analysis_undetected" doc:"Virus total results marked undetected"`
	VTAnalysisTimeout       int64                    `ksql:"vt_analysis_timeout" json:"vt_analysis_timeout"`
	YaraStatus              string                   `ksql:"yara_status" json:"yara_status" doc:"Yara scan status"`
	YaraLastScan            time.Time                `ksql:"yara_last_scan" json:"yara_last_scan" doc:"Last time a yara scan ran"`
	YaraScannedUnpacked     bool                     `ksql:"yara_scanned_unpacked" json:"yara_scanned_unpacked" doc:"Whether yara scanned the unpacked file"`
	YaraDescription         string                   `ksql:"yara_description" json:"yara_description" doc:"Yara LLM summary"`
}

func (c *Download) ModelID() int64 { return c.ID }
