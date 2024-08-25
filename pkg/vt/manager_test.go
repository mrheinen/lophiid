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
		searchDownloadsResponse []database.Download
		errorToReturn           error
		expectedQueueLenAfter   int
	}{
		{
			description:    "runs OK for new download",
			submitResponse: SubmitURLResponse{},
			searchDownloadsResponse: []database.Download{
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
		expectedNumberEvents int64
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
				DownloadsToReturn: []database.Download{
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
			fIpMgr := analysis.FakeIpEventManager{
				AddEventTimesCalled: 0,
			}
			mgr := NewVTBackgroundManager(&fakeDBClient, &fIpMgr, metrics, &fakeVTClient)
			err := mgr.GetFileAnalysis()
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			if fIpMgr.AddEventTimesCalled != test.expectedNumberEvents {
				t.Errorf("expected %d IP events added, but %d were added", test.expectedNumberEvents, fIpMgr.AddEventTimesCalled)
			}

		})
	}
}
