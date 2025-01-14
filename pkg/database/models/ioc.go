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
package models

type IOC struct {
	ID                    int64  `ksql:"id,skipInserts" json:"id" doc:"The ID of the IOC"`
	Source                string `ksql:"source" json:"source" doc:"The source of the IOC"`
	ThreadType            string `ksql:"thread_type" json:"thread_type" doc:"The thread type of the IOC"`
	ThreadTypeDescription string `ksql:"thread_type_description" json:"thread_type_description" doc:"The thread type description of the IOC"`
	IOCType               string `ksql:"ioc_type" json:"ioc_type" doc:"The type of the IOC"`
	IOCTypeDescription    string `ksql:"ioc_type_description" json:"ioc_type_description" doc:"The type description of the IOC"`
	Malware               string `ksql:"malware" json:"malware" doc:"The malware of the IOC"`
	MalwarePrintable      string `ksql:"malware_printable" json:"malware_printable" doc:"The printable form of the malware"`
	MalwareAlias          string `ksql:"malware_alias" json:"malware_alias" doc:"The aliases of the malware"`
	MalpediaUrl           string `ksql:"malpedia_url" json:"malpedia_url" doc:"The URL of the Malpedia entry"`
	AbuseConfidenceLevel  int64  `ksql:"abuse_confidence_level" json:"abuse_confidence_level" doc:"The abuse confidence level of the IOC"`
	AbuseID               string `ksql:"abuse_id" json:"abuse_id" doc:"The abuse.ch ID of the IOC"`
	AbuseReporter         string `ksql:"abuse_reporter" json:"abuse_reporter" doc:"The reporter of the IOC"`
}
