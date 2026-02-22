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
package analysis

import (
	"fmt"
	"log/slog"
	"lophiid/pkg/alerting"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"time"
)

// IpEventManager queues and caches IP related events and periodically stores
// them in the database.
type IpEventManager interface {
	AddEvent(evt *models.IpEvent)
}

type IpEventManagerImpl struct {
	dbClient            database.DatabaseClient
	eventQueue          chan *models.IpEvent
	controlChan         chan bool
	ipCache             *util.StringMapCache[models.IpEvent]
	scanCache           *util.StringMapCache[models.IpEvent]
	metrics             *AnalysisMetrics
	scanMonitorInterval time.Duration
	aggregateScanWindow time.Duration
	alerter             alerting.AlertManagerInterface
	alertEvents         map[string]bool
}

// FakeIpEventManager is used in tests
type FakeIpEventManager struct {
	Events []models.IpEvent
}

func (f *FakeIpEventManager) AddEvent(evt *models.IpEvent) {
	f.Events = append(f.Events, *evt)
}

// NewIpEventManagerImpl creates a new IpEventManagerImpl. The alerter and
// alertEvents parameters are optional and can be nil/empty if alerting is not
// needed.
func NewIpEventManagerImpl(dbClient database.DatabaseClient, ipQueueSize int64, ipCacheDuration time.Duration, scanMonitorWindow time.Duration, aggregateScanWindow time.Duration, metrics *AnalysisMetrics, alerter alerting.AlertManagerInterface, alertEvents map[string]bool) *IpEventManagerImpl {
	ipCache := util.NewStringMapCache[models.IpEvent]("Analysis - IP event cache", ipCacheDuration)
	scanCache := util.NewStringMapCache[models.IpEvent]("Analysis - IP scan cache", ipCacheDuration*2)

	return &IpEventManagerImpl{
		dbClient:            dbClient,
		eventQueue:          make(chan *models.IpEvent, ipQueueSize),
		controlChan:         make(chan bool),
		ipCache:             ipCache,
		scanCache:           scanCache,
		metrics:             metrics,
		scanMonitorInterval: scanMonitorWindow,
		aggregateScanWindow: aggregateScanWindow,
		alerter:             alerter,
		alertEvents:         alertEvents,
	}
}

func (i *IpEventManagerImpl) AddEvent(evt *models.IpEvent) {
	if evt.Subtype == "" {
		evt.Subtype = constants.IpEventSubTypeNone
	}
	i.eventQueue <- evt
}

func (i *IpEventManagerImpl) Start() {
	go i.MonitorQueue()
}

func (i *IpEventManagerImpl) Stop() {
	i.controlChan <- true
}

// MonitorQueue runs in a loop and checks for new events. It writes events that
// expired in the cache to the database.
func (i *IpEventManagerImpl) MonitorQueue() {
	ticker := time.NewTicker(time.Minute * 1)
	scanTicker := time.NewTicker(i.scanMonitorInterval)
	for {
		select {
		case evt := <-i.eventQueue:
			if err := i.ProcessNewEvent(evt); err != nil {
				slog.Error("unable to process event", slog.String("error", err.Error()))
			}
		case <-i.controlChan:
			slog.Info("Stopping IP event handler")
			return

		case <-scanTicker.C:
			i.CreateScanEvents()
		case <-ticker.C:
			i.scanCache.CleanExpired()
			i.metrics.eventQueueGauge.Set(float64(len(i.eventQueue)))
			i.ipCache.CleanExpiredWithCallback(i.handleExpiredEvent)
		}
	}
}

func (i *IpEventManagerImpl) handleExpiredEvent(evt models.IpEvent) bool {
	_, err := i.dbClient.Insert(&evt)
	if err != nil {
		slog.Error("unable to store event",
			slog.String("error", err.Error()),
			slog.String("event", fmt.Sprintf("%+v", evt)))
		return false
	}

	// Send alert if this event type/subtype combination is configured.
	if i.alerter != nil && len(i.alertEvents) > 0 {
		key := util.GenerateAlertEventKey(evt.Type, evt.Subtype)
		if i.alertEvents[key] {
			go i.alerter.SendMessage(fmt.Sprintf("IP Event: %s %s for %s", evt.Type, evt.Subtype, evt.IP))
		}
	}

	return true
}

func (i *IpEventManagerImpl) CreateScanEvents() int {
	const scanThreshold = 3

	eventReturnCount := 0
	scanSubEvents := map[string]bool{
		constants.IpEventSubTypeTrafficClassAttacked: true,
		constants.IpEventSubTypeTrafficClassBrute:    true,
		constants.IpEventSubTypeTrafficClassRecon:    true,
	}

	scanCount := make(map[string]int64)

	for _, evt := range i.ipCache.GetAsMap() {
		if _, ok := scanSubEvents[evt.Subtype]; ok {
			if _, ok := scanCount[evt.IP]; !ok {
				scanCount[evt.IP] = evt.Count
			} else {
				scanCount[evt.IP] += evt.Count
			}
		}
	}

	for ip, cnt := range scanCount {
		if cnt >= scanThreshold {

			// If there already is a scan event for this IP in the cache than skip it.
			// Don't make a new one but DO store the old one again to refresh it's
			// cache timeout timestamp.
			if existingEvt, err := i.scanCache.Get(ip); err == nil {
				duration, err := i.scanCache.GetDurationStored(ip)
				if err != nil {
					slog.Warn("unable to get scan cache duration", slog.String("ip", ip), slog.String("error", err.Error()))
					continue
				}

				// Only update if the age of the scan event is not too old. If it's too
				// old we leave the entry alone and it will eventually expire.
				if duration < i.aggregateScanWindow {
					i.scanCache.Update(ip, *existingEvt)
				}
				continue
			}

			evt := models.IpEvent{
				IP:            ip,
				Type:          constants.IpEventTrafficClass,
				Subtype:       constants.IpEventSubTypeTrafficClassScanned,
				Details:       fmt.Sprintf("found %d events", cnt),
				Source:        constants.IpEventSourceAnalysis,
				SourceRefType: constants.IpEventRefTypeNone,
			}

			i.AddEvent(&evt)
			i.scanCache.Store(ip, evt)

			eventReturnCount += 1
		}
	}

	return eventReturnCount
}

// ProcessNewEvent adds new events to the cache and updates the count for
// existing events.
func (i *IpEventManagerImpl) ProcessNewEvent(evt *models.IpEvent) error {
	cacheKey := fmt.Sprintf("%s-%s", evt.IP, evt.Type)
	entry, err := i.ipCache.Get(cacheKey)
	if err == nil {
		entry.Count += 1
		if err := i.ipCache.Replace(cacheKey, *entry); err != nil {
			return fmt.Errorf("failed to replace cache entry: %w", err)
		}
		return nil
	}

	evt.Count = 1
	evt.FirstSeenAt = time.Now().UTC()
	i.ipCache.Store(cacheKey, *evt)
	return nil
}
