package analysis

import (
	"fmt"
	"lophiid/pkg/database"
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

	im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, time.Minute, WithMetrics(metrics))

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

	im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, time.Minute)

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

			im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, time.Minute)

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

	im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, time.Minute)

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

	fakeDb := &database.FakeDatabaseClient{}

	im := NewIpEventManagerImpl(fakeDb, 100, time.Minute, time.Minute, time.Minute, WithAlerter(alerter), WithAlertEvents(alertEvents))

	evt := models.IpEvent{
		IP:      "1.1.1.1",
		Type:    constants.IpEventSessionInfo,
		Subtype: constants.IpEventSubTypeSuccessivePayload,
	}

	// Call handleExpiredEvent directly to test alerting logic.
	im.handleExpiredEvent(evt)

	// Allow goroutine to complete.
	time.Sleep(time.Millisecond * 10)

	if len(alerter.Messages) != 1 {
		t.Errorf("expected 1 alert message, got %d", len(alerter.Messages))
	}
}

func TestIpEventManagerNoAlertOnNonMatchingEvent(t *testing.T) {
	alerter := &FakeAlerter{}
	alertEvents := map[string]bool{
		util.GenerateAlertEventKey(constants.IpEventSessionInfo, constants.IpEventSubTypeSuccessivePayload): true,
	}

	fakeDb := &database.FakeDatabaseClient{}

	im := NewIpEventManagerImpl(fakeDb, 100, time.Minute, time.Minute, time.Minute, WithAlerter(alerter), WithAlertEvents(alertEvents))

	evt := models.IpEvent{
		IP:      "1.1.1.1",
		Type:    constants.IpEventHostC2,
		Subtype: constants.IpEventSubTypeNone,
	}

	// Call handleExpiredEvent directly to test alerting logic.
	im.handleExpiredEvent(evt)

	// Allow goroutine to complete (if any).
	time.Sleep(time.Millisecond * 10)

	if len(alerter.Messages) != 0 {
		t.Errorf("expected 0 alert messages, got %d", len(alerter.Messages))
	}
}
