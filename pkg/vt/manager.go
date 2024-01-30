package vt

import (
	"fmt"
	"log/slog"
	"loophid/pkg/database"
	"sync"
	"time"
)

type VTManager interface {
	ProcessURLQueue() error
	QueueURL(ip string)
	Start()
	Stop()
}

type FakeVTManager struct {
	ErrorToReturn error
}

func (f *FakeVTManager) ProcessURLQueue() error {
	return f.ErrorToReturn
}
func (f *FakeVTManager) QueueURL(ip string) {}
func (f *FakeVTManager) Start()             {}
func (f *FakeVTManager) Stop()              {}

type VTBackgroundManager struct {
	vtClient VTClientInterface
	dbClient database.DatabaseClient
	urlQmu   sync.Mutex
	urlQueue map[string]bool
	bgChan   chan bool
}

func NewVTBackgroundManager(dbClient database.DatabaseClient, vtClient VTClientInterface) *VTBackgroundManager {
	return &VTBackgroundManager{
		vtClient: vtClient,
		dbClient: dbClient,
		urlQueue: make(map[string]bool),
		bgChan:   make(chan bool),
	}
}

func (v *VTBackgroundManager) QueueURL(url string) {
	v.urlQmu.Lock()
	defer v.urlQmu.Unlock()
	v.urlQueue[url] = true
}

func (v *VTBackgroundManager) URLQueueLen() int {
	v.urlQmu.Lock()
	defer v.urlQmu.Unlock()
	return len(v.urlQueue)
}

func (v *VTBackgroundManager) Start() {
	slog.Info("Starting VT manager")
	ticker := time.NewTicker(time.Second * 60)
	go func() {
		for {
			select {
			case <-v.bgChan:
				ticker.Stop()
				slog.Info("VT manager stopped")
				return
			case <-ticker.C:
				slog.Debug("Processing URL queue", slog.Int("queue_len", len(v.urlQueue)))
				if err := v.ProcessURLQueue(); err != nil {
					if err == ErrQuotaReached {
						slog.Debug("Reached VT quota (URL queue)")
					} else {
						slog.Warn("error processing URL queue", slog.String("error", err.Error()))
					}
				}
			}
		}
	}()
}

func (v *VTBackgroundManager) Stop() {
	slog.Info("Stopping VT manager")
	v.bgChan <- true
}

func (v *VTBackgroundManager) ProcessURLQueue() error {
	v.urlQmu.Lock()
	defer v.urlQmu.Unlock()

	if len(v.urlQueue) == 0 {
		return nil
	}

	for k := range v.urlQueue {
		cRes, err := v.vtClient.SubmitURL(k)
		if err != nil {
			return err
		}

		slog.Info("Submitted URL", slog.String("id", cRes.Data.ID))
		// TODO: add escaping to the URL below
		dls, err := v.dbClient.SearchDownloads(0, 1, fmt.Sprintf("original_url:\"%s\"", k))
		if err != nil {
			slog.Warn("error searching download", slog.String("url", k), slog.String("error", err.Error()))
			delete(v.urlQueue, k)
			continue
		}

		if len(dls) != 1 {
			slog.Warn("did not find database entry for URL", slog.String("url", k))
		} else {
			dl := dls[0]
			dl.VTAnalysisID = cRes.Data.ID
			if err := v.dbClient.Update(&dl); err != nil {
				slog.Warn("error updating download", slog.String("url", k), slog.String("error", err.Error()))
			}
		}
		delete(v.urlQueue, k)
	}

	return nil
}
