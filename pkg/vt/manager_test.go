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
package vt

import (
	"lophiid/pkg/analysis"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util/constants"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

type FakeVTClient struct {
	SubmitURLResponseToReturn    SubmitURLResponse
	FileAnalysisResponseToReturn FileAnalysisResponse
	ErrorToReturn                error
}

func (f *FakeVTClient) Start() {}
func (f *FakeVTClient) Stop()  {}
func (f *FakeVTClient) SubmitURL(url string) (SubmitURLResponse, error) {
	return f.SubmitURLResponseToReturn, f.ErrorToReturn
}
func (f *FakeVTClient) CheckIP(ip string) (CheckIPResponse, error) {
	return CheckIPResponse{}, nil
}
func (f *FakeVTClient) SubmitFile(filename string) (AnalysisResponse, error) {
	return AnalysisResponse{}, nil
}
func (f *FakeVTClient) GetFileAnalysis(id string) (FileAnalysisResponse, error) {
	return f.FileAnalysisResponseToReturn, f.ErrorToReturn
}

func TestProcessURLQueue(t *testing.T) {

	for _, test := range []struct {
		description             string
		submitResponse          SubmitURLResponse
		searchDownloadsResponse []models.Download
		errorToReturn           error
		expectedQueueLenAfter   int
	}{
		{
			description:    "runs OK for new download",
			submitResponse: SubmitURLResponse{},
			searchDownloadsResponse: []models.Download{
				{
					ID: 42,
				},
			},
			errorToReturn:         nil,
			expectedQueueLenAfter: 0,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fakeDBClient := database.FakeDatabaseClient{
				DownloadsToReturn: test.searchDownloadsResponse,
			}
			fakeVTClient := FakeVTClient{
				SubmitURLResponseToReturn: test.submitResponse,
				ErrorToReturn:             test.errorToReturn,
			}

			metrics := CreateVTMetrics(prometheus.NewRegistry())
			fIpMgr := analysis.FakeIpEventManager{}
			mgr := NewVTBackgroundManager(&fakeDBClient, &fIpMgr, metrics, &fakeVTClient)
			mgr.QueueURL("http://www")

			err := mgr.ProcessURLQueue()
			if err != test.errorToReturn {
				t.Errorf("error is unexpected: %s", err)
			}

			if mgr.URLQueueLen() != test.expectedQueueLenAfter {
				t.Errorf("expected %d, got %d", test.expectedQueueLenAfter, mgr.URLQueueLen())
			}
		})
	}
}

func TestManagerGetFileAnalysis(t *testing.T) {

	for _, test := range []struct {
		description          string
		expectedNumberEvents int
		analysisResponse     FileAnalysisResponse
	}{
		{
			description:          "runs ok, detects malicious",
			expectedNumberEvents: 2,
			analysisResponse: FileAnalysisResponse{
				Data: FileAnalysisData{
					Attributes: FileAnalysisAttributes{
						Stats: AnalysisStats{
							Malicious:  10,
							Undetected: 10,
							Suspicious: 0,
							Harmless:   10,
							Timeout:    10,
						},
						Status: "completed",
						Results: map[string]EngineResult{
							"Fortinet": {
								Result: "something/Virus",
							},
						},
					},
				},
			},
		},
		{
			description:          "runs ok, detects suspicious",
			expectedNumberEvents: 2,
			analysisResponse: FileAnalysisResponse{
				Data: FileAnalysisData{
					Attributes: FileAnalysisAttributes{
						Stats: AnalysisStats{
							Malicious:  0,
							Undetected: 10,
							Suspicious: 10,
							Harmless:   10,
							Timeout:    10,
						},
						Status: "completed",
						Results: map[string]EngineResult{
							"Fortinet": {
								Result: "something/Virus",
							},
						},
					},
				},
			},
		},

		{
			description:          "runs ok, detects nothing",
			expectedNumberEvents: 0,
			analysisResponse: FileAnalysisResponse{
				Data: FileAnalysisData{
					Attributes: FileAnalysisAttributes{
						Stats: AnalysisStats{
							Malicious:  0,
							Undetected: 0,
							Suspicious: 0,
							Harmless:   0,
							Timeout:    0,
						},
						Status: "completed",
						Results: map[string]EngineResult{
							"Fortinet": {
								Result: "something/Virus",
							},
						},
					},
				},
			},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fakeDBClient := database.FakeDatabaseClient{
				DownloadsToReturn: []models.Download{
					{
						ID:                 42,
						VTFileAnalysisDone: false,
						VTFileAnalysisID:   "AAAA",
					},
				},
			}
			fakeVTClient := FakeVTClient{
				FileAnalysisResponseToReturn: test.analysisResponse,
				ErrorToReturn:                nil,
			}

			metrics := CreateVTMetrics(prometheus.NewRegistry())
			fIpMgr := analysis.FakeIpEventManager{}
			mgr := NewVTBackgroundManager(&fakeDBClient, &fIpMgr, metrics, &fakeVTClient)
			err := mgr.GetFileAnalysis()
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			if len(fIpMgr.Events) != test.expectedNumberEvents {
				t.Errorf("expected %d IP events added, but %d were added", test.expectedNumberEvents, len(fIpMgr.Events))
			}

		})
	}
}

func TestGetEventsForDownload(t *testing.T) {
	for _, test := range []struct {
		description    string
		download       models.Download
		request        models.Request
		expectedEvents int
		expectedIP     string
		expectedDomain string
		isMalwareNew   bool
	}{
		{
			description: "returns events OK",
			download: models.Download{
				RequestID: 42,
				IP:        "1.1.1.1",
				Host:      "1.1.1.1",
			},
			request: models.Request{
				ID:       22,
				SourceIP: "1.1.1.1",
			},
			expectedEvents: 2,
			expectedIP:     "1.1.1.1",
			expectedDomain: "",
			isMalwareNew:   true,
		},
		{
			description: "returns events with domain port",
			download: models.Download{
				RequestID: 42,
				IP:        "1.1.1.1",
				Host:      "example.org:888",
			},
			request: models.Request{
				ID:       22,
				SourceIP: "1.1.1.1",
			},
			expectedEvents: 2,
			expectedIP:     "1.1.1.1",
			expectedDomain: "example.org",
			isMalwareNew:   true,
		},
		{
			description: "returns events with domain",
			download: models.Download{
				RequestID: 42,
				IP:        "1.1.1.1",
				Host:      "example.org",
			},
			request: models.Request{
				ID:       22,
				SourceIP: "1.1.1.1",
			},
			expectedEvents: 2,
			expectedIP:     "1.1.1.1",
			expectedDomain: "example.org",
			isMalwareNew:   true,
		},
		{
			description: "returns events with domain, malware old",
			download: models.Download{
				RequestID: 42,
				IP:        "1.1.1.1",
				Host:      "example.org",
			},
			request: models.Request{
				ID:       22,
				SourceIP: "1.1.1.1",
			},
			expectedEvents: 2,
			expectedIP:     "1.1.1.1",
			expectedDomain: "example.org",
			isMalwareNew:   false,
		},

	} {

		t.Run(test.description, func(t *testing.T) {
			fakeDBClient := database.FakeDatabaseClient{
				RequestToReturn: test.request,
			}
			fakeVTClient := FakeVTClient{}

			metrics := CreateVTMetrics(prometheus.NewRegistry())
			fIpMgr := analysis.FakeIpEventManager{}
			mgr := NewVTBackgroundManager(&fakeDBClient, &fIpMgr, metrics, &fakeVTClient)

			events := mgr.GetEventsForDownload(&test.download, test.isMalwareNew)
			if len(events) != test.expectedEvents {
				t.Errorf("expected %d events, got %d", test.expectedEvents, len(events))
			}

			for _, evt := range events {
				if evt.IP != test.expectedIP {
					t.Errorf("expected IP %s, got %s", test.expectedIP, evt.IP)
				}

				expectedSubType := constants.IpEventSubTypeMalwareOld
				if test.isMalwareNew {
					expectedSubType = constants.IpEventSubTypeMalwareNew
				}

				if evt.Subtype != expectedSubType {
					t.Errorf("expected subtype %s, got %s", expectedSubType, evt.Subtype)
				}

				if evt.Source != constants.IpEventSourceVT {
					t.Errorf("expected source %s, got %s", constants.IpEventSourceVT, evt.Source)
				}
			}

			if events[0].Domain != test.expectedDomain {
				t.Errorf("expected domain %s, got %s", test.expectedDomain, events[0].Domain)
			}
		})
	}
}
