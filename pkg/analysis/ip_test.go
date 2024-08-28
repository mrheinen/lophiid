package analysis

import (
	"fmt"
	"lophiid/pkg/database"
	"lophiid/pkg/util/constants"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestIpEventManagerStoresOnceOk(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := CreateAnalysisMetrics(reg)

	im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, metrics)

	testIp := "1.1.1.1"
	testEvtName := "boof"

	// Store it once
	im.ProcessNewEvent(&database.IpEvent{
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

	im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, metrics)

	testIp := "1.1.1.1"
	testEvtName := "boof"

	im.ProcessNewEvent(&database.IpEvent{
		Type: testEvtName,
		IP:   testIp,
	})

	im.ProcessNewEvent(&database.IpEvent{
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
		events          []database.IpEvent
		expectScanEvent bool
	}{
		{
			description: "no scan event",
			events: []database.IpEvent{
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
			events: []database.IpEvent{
				{
					Type: constants.IpEventAttacked,
					IP:   "1.1.1.1",
				},
				{
					Type: constants.IpEventAttacked,
					IP:   "1.1.1.1",
				},
				{
					Type: constants.IpEventAttacked,
					IP:   "1.1.1.1",
				},
			},
			expectScanEvent: true,
		},

		{
			description: "detects scan, combined event",
			events: []database.IpEvent{
				{
					Type: constants.IpEventRecon,
					IP:   "1.1.1.1",
				},
				{
					Type: constants.IpEventAttacked,
					IP:   "1.1.1.1",
				},
				{
					Type: constants.IpEventAttacked,
					IP:   "1.1.1.1",
				},
			},
			expectScanEvent: true,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			metrics := CreateAnalysisMetrics(reg)
			im := NewIpEventManagerImpl(nil, 100, 10, time.Minute, metrics)

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
