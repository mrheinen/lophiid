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
	"fmt"
	"log/slog"
	"lophiid/pkg/analysis"
	"lophiid/pkg/database"
	"sync"
	"time"
)

type VTManager interface {
	ProcessURLQueue() error
	QueueURL(ip string)
	SubmitFiles() error
	Start()
	Stop()
}

type FakeVTManager struct {
	ErrorToReturn error
}

func (f *FakeVTManager) ProcessURLQueue() error {
	return f.ErrorToReturn
}
func (f *FakeVTManager) SubmitFiles() error {
	return f.ErrorToReturn
}
func (f *FakeVTManager) QueueURL(ip string) {}
func (f *FakeVTManager) Start()             {}
func (f *FakeVTManager) Stop()              {}

// ProbeRequestToDatabaseRequest transforms aHandleProbeRequest to a

type VTBackgroundManager struct {
	vtClient       VTClientInterface
	dbClient       database.DatabaseClient
	urlQmu         sync.Mutex
	urlQueue       map[string]bool
	bgChan         chan bool
	metrics        *VTMetrics
	ipEventManager analysis.IpEventManager
}

// NewVTBackgroundManager creates a new VTBackgroundManager instance.
//
// Parameters:
// - dbClient: database client
// - metrics: pointer to VTMetrics
// - vtClient: VTClientInterface
// Returns a pointer to VTBackgroundManager.
func NewVTBackgroundManager(dbClient database.DatabaseClient, ipEventManager analysis.IpEventManager, metrics *VTMetrics, vtClient VTClientInterface) *VTBackgroundManager {
	return &VTBackgroundManager{
		vtClient:       vtClient,
		dbClient:       dbClient,
		urlQueue:       make(map[string]bool),
		bgChan:         make(chan bool),
		metrics:        metrics,
		ipEventManager: ipEventManager,
	}
}

func (v *VTBackgroundManager) QueueURL(url string) {
	v.urlQmu.Lock()
	defer v.urlQmu.Unlock()
	fmt.Printf("VT: adding URL to queue: %s\n", url)
	v.urlQueue[url] = true
}

func (v *VTBackgroundManager) URLQueueLen() int {
	v.urlQmu.Lock()
	defer v.urlQmu.Unlock()
	return len(v.urlQueue)
}

func (v *VTBackgroundManager) Start() {
	slog.Info("Starting VT manager")
	ticker := time.NewTicker(time.Second * 300)
	go func() {
		for {
			select {
			case <-v.bgChan:
				ticker.Stop()
				slog.Info("VT manager stopped")
				return
			case <-ticker.C:
				slog.Debug("Fetching analysis")
				startTime := time.Now()
				err := v.GetFileAnalysis()
				v.metrics.fileSubmitResponseTime.Observe(time.Since(startTime).Seconds())
				if err != nil {
					slog.Warn("error fetching file analysis", slog.String("error", err.Error()))
				}

				slog.Debug("Processing URL queue", slog.Int("queue_len", len(v.urlQueue)))
				if err = v.ProcessURLQueue(); err != nil {
					if err == ErrQuotaReached {
						slog.Debug("Reached VT quota (URL queue)")
					} else {
						slog.Warn("error processing URL queue", slog.String("error", err.Error()))
					}
				}

				slog.Debug("Submitting files")
				err = v.SubmitFiles()
				if err != nil {
					slog.Warn("error submitting file", slog.String("error", err.Error()))
				}
			}
		}
	}()

}

func (v *VTBackgroundManager) Stop() {
	slog.Info("Stopping VT manager")
	v.bgChan <- true
}

func (v *VTBackgroundManager) SubmitFiles() error {
	dls, err := v.dbClient.SearchDownloads(0, 10, "vt_file_analysis_submitted:false")
	if err != nil {
		return fmt.Errorf("error searching: %w", err)
	}

	for _, dl := range dls {
		slog.Info("Submitting file", slog.String("file", dl.FileLocation))
		startTime := time.Now()
		cRes, err := v.vtClient.SubmitFile(dl.FileLocation)
		v.metrics.fileSubmitResponseTime.Observe(time.Since(startTime).Seconds())
		v.metrics.apiCallsCount.WithLabelValues("file_submit").Add(1)
		if err != nil {
			slog.Warn("error submitting file", slog.String("error", err.Error()))
		} else {
			dl.VTFileAnalysisID = cRes.Data.ID
		}

		dl.VTFileAnalysisSubmitted = true
		err = v.dbClient.Update(&dl)
		if err != nil {
			return fmt.Errorf("error updating download: %w", err)
		}
	}

	return nil
}

// Prefered engines for which we store the results for displaying in the UI
var PreferedFileResultEngines = []string{"Fortinet", "Avast", "BitDefender", "Microsoft", "McAfee", "TrendMicro"}

func (v *VTBackgroundManager) GetFileAnalysis() error {
	dls, err := v.dbClient.SearchDownloads(0, 10, "vt_file_analysis_done:false")
	if err != nil {
		return fmt.Errorf("error searching: %w", err)
	}

	for _, dl := range dls {
		slog.Info("Fetching analysis for file", slog.String("file", dl.FileLocation))
		cRes, err := v.vtClient.GetFileAnalysis(dl.VTFileAnalysisID)
		v.metrics.apiCallsCount.WithLabelValues("get_analysis").Add(1)
		if err != nil {
			slog.Warn("error fetching analysis", slog.String("error", err.Error()))
			continue
		}

		if cRes.Data.Attributes.Status != "completed" {
			continue
		}

		dl.VTAnalysisMalicious = cRes.Data.Attributes.Stats.Malicious
		dl.VTAnalysisUndetected = cRes.Data.Attributes.Stats.Undetected
		dl.VTAnalysisSuspicious = cRes.Data.Attributes.Stats.Suspicious
		dl.VTAnalysisTimeout = cRes.Data.Attributes.Stats.Timeout
		dl.VTAnalysisHarmless = cRes.Data.Attributes.Stats.Harmless
		dl.VTFileAnalysisDone = true

		if dl.VTAnalysisMalicious > 0 || dl.VTAnalysisSuspicious > 0 {
			// Register the IP hosting the malware.
			evt := database.IpEvent{
				IP:        dl.IP,
				Type:      analysis.IpEventHostedMalware,
				RequestID: dl.RequestID,
				Details:   fmt.Sprintf("Hosted file that VirusTotal reported on (%d malicious, %d suspicious)", dl.VTAnalysisMalicious, dl.VTAnalysisSuspicious),
			}

			if dl.Host != dl.IP {
				// TODO: consider resolving the domain and also adding any additional
				// IPs that yields.
				evt.Domain = dl.Host
			}

			v.ipEventManager.AddEvent(&evt)

			r, err := v.dbClient.GetRequestByID(dl.RequestID)
			if err != nil {
				slog.Error("unexpected error, cannot find request", slog.String("error", err.Error()), slog.Int64("request_id", dl.RequestID))
			} else {
				v.ipEventManager.AddEvent(&database.IpEvent{
					IP:        r.SourceIP,
					Type:      analysis.IpEventAttacked,
					RequestID: dl.RequestID,
					Details:   fmt.Sprintf("Sent payload that VirusTotal reported on (%d malicious, %d suspicious)", dl.VTAnalysisMalicious, dl.VTAnalysisSuspicious),
				})
			}
		}

		// Append only the results from our prefered engines.
		for _, en := range PreferedFileResultEngines {
			if result, ok := cRes.Data.Attributes.Results[en]; ok && result.Result != "" {
				newResult := fmt.Sprintf("%s: %s", en, result.Result)
				dl.VTFileAnalysisResult = append(dl.VTFileAnalysisResult, newResult)
			}
		}

		err = v.dbClient.Update(&dl)
		if err != nil {
			return fmt.Errorf("error updating download: %w", err)
		}
	}

	return nil
}

func (v *VTBackgroundManager) ProcessURLQueue() error {
	v.urlQmu.Lock()
	defer v.urlQmu.Unlock()

	fmt.Printf("VT ProcessURLQueue. Queue len: %d\n", len(v.urlQueue))
	if len(v.urlQueue) == 0 {
		return nil
	}

	for k := range v.urlQueue {
		startTime := time.Now()
		fmt.Printf("VT - Submiting URL: %s\n", k)
		cRes, err := v.vtClient.SubmitURL(k)
		v.metrics.urlSubmitResponseTime.Observe(time.Since(startTime).Seconds())
		v.metrics.apiCallsCount.WithLabelValues("submit_url").Add(1)
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
			dl.VTURLAnalysisID = cRes.Data.ID

			if err := v.dbClient.Update(&dl); err != nil {
				slog.Warn("error updating download", slog.String("url", k), slog.String("error", err.Error()))
			}
		}
		delete(v.urlQueue, k)
	}

	return nil
}
