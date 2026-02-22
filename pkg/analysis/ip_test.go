package analysis

import (
	"fmt"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// FakeAlerter is a mock alerter for testing that implements Alerter.
type FakeAlerter struct {
	Messages []string
}

func (f *FakeAlerter) SendMessage(mesg string) {
	f.Messages = append(f.Messages, mesg)
}

func TestIpEventManagerStoresOnceOk(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := CreateAnalysisMetrics(reg)

	im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, time.Minute, metrics, nil, nil)

	testIp := "1.1.1.1"
	testEvtName := "boof"

	// Store it once
	im.ProcessNewEvent(&models.IpEvent{
		Type: testEvtName,
		IP:   testIp,
	})

	entry, err := im.ipCache.Get(fmt.Sprintf("%s-%s", testIp, testEvtName))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if entry.Count != 1 {
		t.Errorf("expected 1, got %d", entry.Count)
	}
}

func TestIpEventManagerStoresTwiceOk(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := CreateAnalysisMetrics(reg)

	im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, time.Minute, metrics, nil, nil)

	testIp := "1.1.1.1"
	testEvtName := "boof"

	im.ProcessNewEvent(&models.IpEvent{
		Type: testEvtName,
		IP:   testIp,
	})

	im.ProcessNewEvent(&models.IpEvent{
		Type: testEvtName,
		IP:   testIp,
	})

	entry, err := im.ipCache.Get(fmt.Sprintf("%s-%s", testIp, testEvtName))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if entry.Count != 2 {
		t.Errorf("expected 2, got %d", entry.Count)
	}
}

func TestIpEventManagerCreatesScanEvents(t *testing.T) {
	for _, test := range []struct {
		description     string
		events          []models.IpEvent
		expectScanEvent bool
	}{
		{
			description: "no scan event",
			events: []models.IpEvent{
				{
					Type: constants.IpEventHostC2,
					IP:   "1.1.1.1",
				},
				{
					Type: constants.IpEventHostC2,
					IP:   "1.1.1.1",
				},
				{
					Type: constants.IpEventHostC2,
					IP:   "1.1.1.1",
				},
			},
			expectScanEvent: false,
		},
		{
			description: "detects scan, same event",
			events: []models.IpEvent{
				{
					Type:    constants.IpEventTrafficClass,
					Subtype: constants.IpEventSubTypeTrafficClassAttacked,
					IP:      "1.1.1.1",
				},

				{
					Type:    constants.IpEventTrafficClass,
					Subtype: constants.IpEventSubTypeTrafficClassAttacked,
					IP:      "1.1.1.1",
				},
				{
					Type:    constants.IpEventTrafficClass,
					Subtype: constants.IpEventSubTypeTrafficClassAttacked,
					IP:      "1.1.1.1",
				},
			},
			expectScanEvent: true,
		},

		{
			description: "detects scan, combined event",
			events: []models.IpEvent{
				{
					Type:    constants.IpEventTrafficClass,
					Subtype: constants.IpEventSubTypeTrafficClassRecon,
					IP:      "1.1.1.1",
				},

				{
					Type:    constants.IpEventTrafficClass,
					Subtype: constants.IpEventSubTypeTrafficClassAttacked,
					IP:      "1.1.1.1",
				},
				{
					Type:    constants.IpEventTrafficClass,
					Subtype: constants.IpEventSubTypeTrafficClassAttacked,
					IP:      "1.1.1.1",
				},
			},
			expectScanEvent: true,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			metrics := CreateAnalysisMetrics(reg)
			im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, time.Minute, metrics, nil, nil)

			for _, evt := range test.events {
				im.ProcessNewEvent(&evt)
			}

			numberEvents := im.CreateScanEvents()
			if !test.expectScanEvent && numberEvents > 0 {
				t.Errorf("expected scan event: %t", test.expectScanEvent)
			} else if test.expectScanEvent && numberEvents == 0 {
				t.Errorf("expected scan event but got nothing")
			}

		})
	}
}

func TestIpEventManagerCreatesNoDuplicateScanEvents(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := CreateAnalysisMetrics(reg)
	im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, time.Minute, metrics, nil, nil)

	im.ProcessNewEvent(&models.IpEvent{
		IP:      "1.1.1.1",
		Type:    constants.IpEventTrafficClass,
		Subtype: constants.IpEventSubTypeTrafficClassAttacked,
	})

	im.ProcessNewEvent(&models.IpEvent{
		IP:      "1.1.1.1",
		Type:    constants.IpEventTrafficClass,
		Subtype: constants.IpEventSubTypeTrafficClassAttacked,
	})

	im.ProcessNewEvent(&models.IpEvent{
		IP:      "1.1.1.1",
		Type:    constants.IpEventTrafficClass,
		Subtype: constants.IpEventSubTypeTrafficClassAttacked,
	})

	numberEvents := im.CreateScanEvents()
	if numberEvents != 1 {
		t.Errorf("expected 1 scan event, got %d", numberEvents)
	}

	numberEvents = im.CreateScanEvents()
	if numberEvents != 0 {
		t.Errorf("expected 0 scan event, got %d", numberEvents)
	}
}

func TestIpEventManagerSendsAlertOnMatchingEvent(t *testing.T) {
	alerter := &FakeAlerter{}
	alertEvents := map[string]bool{
		util.GenerateAlertEventKey(constants.IpEventSessionInfo, constants.IpEventSubTypeSuccessivePayload): true,
	}

	reg := prometheus.NewRegistry()
	metrics := CreateAnalysisMetrics(reg)
	// Use a very short cache duration so entries expire immediately.
	im := NewIpEventManagerImpl(nil, 100, time.Millisecond, time.Minute, time.Minute, metrics, alerter, alertEvents)

	// Add an event that should trigger an alert.
	im.ipCache.Store("test-key", models.IpEvent{
		IP:      "1.1.1.1",
		Type:    constants.IpEventSessionInfo,
		Subtype: constants.IpEventSubTypeSuccessivePayload,
	})

	// Wait for cache entry to expire.
	time.Sleep(time.Millisecond * 5)

	// Trigger cache cleanup with callback that mimics MonitorQueue logic.
	im.ipCache.CleanExpiredWithCallback(func(evt models.IpEvent) bool {
		if im.alerter != nil && len(im.alertEvents) > 0 {
			key := util.GenerateAlertEventKey(evt.Type, evt.Subtype)
			if im.alertEvents[key] {
				im.alerter.SendMessage(fmt.Sprintf("IP Event: %s %s for %s", evt.Type, evt.Subtype, evt.IP))
			}
		}
		return true
	})

	if len(alerter.Messages) != 1 {
		t.Errorf("expected 1 alert message, got %d", len(alerter.Messages))
	}
}

func TestIpEventManagerNoAlertOnNonMatchingEvent(t *testing.T) {
	alerter := &FakeAlerter{}
	alertEvents := map[string]bool{
		util.GenerateAlertEventKey(constants.IpEventSessionInfo, constants.IpEventSubTypeSuccessivePayload): true,
	}

	reg := prometheus.NewRegistry()
	metrics := CreateAnalysisMetrics(reg)
	// Use a very short cache duration so entries expire immediately.
	im := NewIpEventManagerImpl(nil, 100, time.Millisecond, time.Minute, time.Minute, metrics, alerter, alertEvents)

	// Add an event that should NOT trigger an alert.
	im.ipCache.Store("test-key", models.IpEvent{
		IP:      "1.1.1.1",
		Type:    constants.IpEventHostC2,
		Subtype: constants.IpEventSubTypeNone,
	})

	// Wait for cache entry to expire.
	time.Sleep(time.Millisecond * 5)

	// Trigger cache cleanup with callback that mimics MonitorQueue logic.
	im.ipCache.CleanExpiredWithCallback(func(evt models.IpEvent) bool {
		if im.alerter != nil && len(im.alertEvents) > 0 {
			key := util.GenerateAlertEventKey(evt.Type, evt.Subtype)
			if im.alertEvents[key] {
				im.alerter.SendMessage(fmt.Sprintf("IP Event: %s %s for %s", evt.Type, evt.Subtype, evt.IP))
			}
		}
		return true
	})

	if len(alerter.Messages) != 0 {
		t.Errorf("expected 0 alert messages, got %d", len(alerter.Messages))
	}
}
