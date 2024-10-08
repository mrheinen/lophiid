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
//
package alerting

import (
	"fmt"
	"log/slog"
	"lophiid/pkg/util"
	"sync"
	"time"
)

var (
	// Messages will not exceed this size. Note that this was chosen because of
	// Telegram. It's important to keep an eye on new alerter implementations to
	// make sure that they don't have a smaller maximum message size.
	maxMessageSize int = 4096
)

// Alerter is an interface for alerter instances which each implement the logic
// necessary to send a message to a specific platform. E.g. there is a
// TelegramAlerter which sends messages to chat.
type Alerter interface {
	Init() error
	SendMessage(mesg string) error
}

type AlertManager struct {
	alerters      []Alerter
	alertInterval time.Duration
	msgBuffer     map[string]int
	mu            sync.Mutex
	bgChan        chan bool
}

// Returns a new alert manager. The interval indicates in minutes the time
// during which message should be buffered, aggregated and then send.
func NewAlertManager(alertInterval time.Duration) *AlertManager {
	am := &AlertManager{
		alertInterval: alertInterval,
		msgBuffer:     make(map[string]int),
		bgChan:        make(chan bool),
	}

	return am
}

// Start starts the go routine that handles buffered messages. The routing is
// stopped by the Stop() method.
func (a *AlertManager) Start() {
	slog.Info("starting alert manager")
	ticker := time.NewTicker(a.alertInterval)
	go func() {
		for {
			select {
			case <-a.bgChan:
				ticker.Stop()
				slog.Info("alert manager stopped")
				return
			case <-ticker.C:
				a.EmptyBuffer()
			}
		}
	}()
}

func (a *AlertManager) Stop() {
	slog.Info("stopping alert manager")
	a.bgChan <- true
}

// AddAlerter initializes the alerter and adds it to the internal array.
func (a *AlertManager) AddAlerter(al Alerter) error {
	if err := al.Init(); err != nil {
		return fmt.Errorf("upon init: %s", err)
	}

	a.alerters = append(a.alerters, al)
	return nil
}

// SendMessage will send the given message using all the alterers. This method
// will log failures but will continue on purpose.
func (a *AlertManager) SendMessage(mesg string) {
	for _, alerter := range a.alerters {
		if err := alerter.SendMessage(mesg); err != nil {
			name := util.GetStructName(alerter)
			slog.Warn("could not send message", slog.String("alerter", name), slog.String("error", err.Error()))
		}
	}
}

// SendBufferedMessage adds the message to the buffer from which it later will
// be send. Duplicate messages are aggregated.
func (a *AlertManager) SendBufferedMessage(mesg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.msgBuffer[mesg]; ok {
		a.msgBuffer[mesg] = a.msgBuffer[mesg] + 1
	} else {
		a.msgBuffer[mesg] = 1
	}
}

func (a *AlertManager) EmptyBuffer() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Return early.
	if len(a.msgBuffer) == 0 {
		return
	}

	message := ""
	for k, v := range a.msgBuffer {
		// If it exceeds our maximum size + a small safety buffer,
		// send it already and start a new message.
		if len(message)+len(k) > (maxMessageSize - 50) {
			a.SendMessage(message)
			message = ""
			continue
		}

		suffix := ""

		if v > 1 {
			suffix = fmt.Sprintf(" (times: %d)", v)
		}

		if message == "" {
			message = fmt.Sprintf("%s%s", k, suffix)
		} else {
			message = fmt.Sprintf("%s\n%s%s", message, k, suffix)
		}
	}

	a.msgBuffer = make(map[string]int)
	a.SendMessage(message)
}
