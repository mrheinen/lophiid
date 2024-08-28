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
	"lophiid/pkg/database"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"time"
)

// IpEventManager queues and caches IP related events and periodically stores
// them in the database.
type IpEventManager interface {
	AddEvent(evt *database.IpEvent)
}

type IpEventManagerImpl struct {
	dbClient            database.DatabaseClient
	eventQueue          chan *database.IpEvent
	controlChan         chan bool
	ipCache             *util.StringMapCache[database.IpEvent]
	metrics             *AnalysisMetrics
	scanMonitorInterval time.Duration
}

// FakeIpEventManager is used in tests
type FakeIpEventManager struct {
	Events []database.IpEvent
}

func (f *FakeIpEventManager) AddEvent(evt *database.IpEvent) {
	f.Events = append(f.Events, *evt)
}

func NewIpEventManagerImpl(dbClient database.DatabaseClient, ipQueueSize int64, ipCacheDuration time.Duration, scanMonitorWindow time.Duration, metrics *AnalysisMetrics) *IpEventManagerImpl {
	ipCache := util.NewStringMapCache[database.IpEvent]("IP event cache", ipCacheDuration)

	return &IpEventManagerImpl{
		dbClient:            dbClient,
		eventQueue:          make(chan *database.IpEvent, ipQueueSize),
		controlChan:         make(chan bool),
		ipCache:             ipCache,
		metrics:             metrics,
		scanMonitorInterval: scanMonitorWindow,
	}
}

func (i *IpEventManagerImpl) AddEvent(evt *database.IpEvent) {
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
			i.metrics.eventQueueGauge.Set(float64(len(i.eventQueue)))
			i.ipCache.CleanExpiredWithCallback(func(evt database.IpEvent) bool {
				_, err := i.dbClient.Insert(&evt)
				if err != nil {
					slog.Error("unable to store event", slog.String("error", err.Error()))
				}

				return err == nil
			})
		}
	}
}

func (i *IpEventManagerImpl) CreateScanEvents() int {
	const scanThreshold = 3
	eventReturnCount := 0
	scanEvents := map[string]bool{
		constants.IpEventAttacked: true,
		constants.IpEventRecon:    true,
	}

	// Store existing scan events so we don't make duplicates.
	existingScannedEvents := map[string]bool{}

	scanCount := make(map[string]int64)

	for _, evt := range i.ipCache.GetAsMap() {
		if _, ok := scanEvents[evt.Type]; ok {
			if _, ok := scanCount[evt.IP]; !ok {
				scanCount[evt.IP] = evt.Count
			} else {
				scanCount[evt.IP] += evt.Count
			}
		}

		if evt.Type == constants.IpEventScanned {
			existingScannedEvents[evt.IP] = true
		}
	}

	for ip, cnt := range scanCount {
		if cnt >= scanThreshold {

			// Avoid double events
			if _, ok := existingScannedEvents[ip]; ok {
				continue
			}

			// TODO: Consider to check if such an event was already created during the
			// previous runs of this method. Could be useful to reduce noise.
			i.AddEvent(&database.IpEvent{
				IP:      ip,
				Type:    constants.IpEventScanned,
				Details: fmt.Sprintf("found %d events", cnt),
			})
			eventReturnCount += 1
		}
	}

	return eventReturnCount
}

// ProcessNewEvent adds new events to the cache and updates the count for
// existing events.
func (i *IpEventManagerImpl) ProcessNewEvent(evt *database.IpEvent) error {
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
	i.ipCache.Store(cacheKey, *evt)
	return nil
}
