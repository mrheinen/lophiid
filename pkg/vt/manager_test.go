package vt

import (
	"loophid/pkg/database"
	"testing"
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

			mgr := NewVTBackgroundManager(&fakeDBClient, &fakeVTClient)
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

		FileAnalysisResponseToReturn: FileAnalysisResponse{
			Data: FileAnalysisData{
				Attributes: FileAnalysisAttributes{
					Stats: AnalysisStats{
						Malicious:  10,
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
		ErrorToReturn: nil,
	}

	mgr := NewVTBackgroundManager(&fakeDBClient, &fakeVTClient)
	err := mgr.GetFileAnalysis()
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}
