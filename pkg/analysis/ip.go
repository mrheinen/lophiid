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
	"time"
)

// IpEventManager queues and caches IP related events and periodically stores
// them in the database.
type IpEventManager interface {
	AddEvent(evt *database.IpEvent)
}

type IpEventManagerImpl struct {
	dbClient    database.DatabaseClient
	eventQueue  chan *database.IpEvent
	controlChan chan bool
	ipCache     *util.StringMapCache[database.IpEvent]
	metrics     *AnalysisMetrics
}

func NewIpEventManagerImpl(dbClient database.DatabaseClient, ipQueueSize int64, ipCacheDuration time.Duration, metrics *AnalysisMetrics) *IpEventManagerImpl {
	ipCache := util.NewStringMapCache[database.IpEvent]("IP event cache", ipCacheDuration)

	return &IpEventManagerImpl{
		dbClient:    dbClient,
		eventQueue:  make(chan *database.IpEvent, ipQueueSize),
		controlChan: make(chan bool),
		ipCache:     ipCache,
		metrics:     metrics,
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
	for {
		select {
		case evt := <-i.eventQueue:
			if err := i.ProcessNewEvent(evt); err != nil {
				slog.Error("unable to process event", slog.String("error", err.Error()))
			}
		case <-i.controlChan:
			slog.Info("Stopping IP event handler")
			return

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

// ProcessNewEvent adds new events to the cache and updates the count for
// existing events.
func (i *IpEventManagerImpl) ProcessNewEvent(evt *database.IpEvent) error {
	cacheKey := fmt.Sprintf("%s-%s", evt.IP, evt.Type)
	entry, err := i.ipCache.Get(cacheKey)
	if err == nil {
		entry.Count += 1
		i.ipCache.Replace(cacheKey, *entry)
		return nil
	}

	evt.Count = 1
	i.ipCache.Store(cacheKey, *evt)
	return nil
}
