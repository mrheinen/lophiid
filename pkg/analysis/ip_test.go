package analysis

import (
	"fmt"
	"lophiid/pkg/database"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestIpEventManagerStoresOnceOk(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := CreateAnalysisMetrics(reg)

	im := NewIpEventManagerImpl(nil, 100, 10, metrics)

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

	im := NewIpEventManagerImpl(nil, 100, 10, metrics)

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
