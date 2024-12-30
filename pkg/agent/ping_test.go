package agent

import (
	"strings"
	"testing"
	"time"
)

func TestProbingPinger_PingTimesOut(t *testing.T) {
	pp := NewProbingPingRunner(time.Millisecond)
	_, err := pp.Ping("8.8.8.8", 10)

	if err == nil {
		t.Error("expected error, got nil")
	} else {
		if strings.Contains(err.Error(), "permission") {
			t.Errorf("You need to allow ping permissions")
		}

		if !strings.Contains(err.Error(), "timeout") {
			t.Errorf("expected timeout, got %s", err)
		}
	}
}

func TestProbingPinger_PingWorks(t *testing.T) {
	pp := NewProbingPingRunner(time.Second * 5)
	res, err := pp.Ping("::1", 1)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if res.PacketsSent != 1 {
		t.Errorf("unexpected amount packets sent: %d", res.PacketsSent)
	}
	if res.PacketsReceived != 1 {
		t.Errorf("unexpected amount packets received: %d", res.PacketsReceived)
	}

}
