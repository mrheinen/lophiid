package vt

import (
	"loophid/pkg/database"
	"testing"
)

type FakeVTClient struct {
	SubmitURLResponseToReturn SubmitURLResponse
	ErrorToReturn             error
}

func (f *FakeVTClient) Start() {}
func (f *FakeVTClient) Stop()  {}
func (f *FakeVTClient) SubmitURL(url string) (SubmitURLResponse, error) {
	return f.SubmitURLResponseToReturn, f.ErrorToReturn
}
func (f *FakeVTClient) CheckIP(ip string) (CheckIPResponse, error) {
	return CheckIPResponse{}, nil
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
