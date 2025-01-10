package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

const maxPings = 10

type Pinger interface {
	RunWithContext(ctx context.Context) error
	Statistics() *probing.Statistics
}

// PingResult is used for easily sharing of the results to the caller.
type PingResult struct {
	PacketsSent     int64
	PacketsReceived int64
	AverageRttMs    int64
	MinRttMs        int64
	MaxRttMs        int64
}

type PingRunner interface {
	Ping(address string, count int64) (PingResult, error)
}

type ProbingPingRunner struct {
	timeout time.Duration
}

// NewProbingPinger returns a new ProbingPinger
func NewProbingPingRunner(timeout time.Duration) *ProbingPingRunner {
	return &ProbingPingRunner{
		timeout: timeout,
	}
}

// Ping runs a ping with the specified amount.
func (p *ProbingPingRunner) Ping(address string, count int64) (PingResult, error) {
    if count <= 0 {
        return PingResult{}, fmt.Errorf("invalid ping count: %d", count)
    }
    if count > maxPings {
        slog.Warn("ping amount too high, using max", slog.Int("max", maxPings))
        count = maxPings
    }
	if err != nil {
		return PingResult{}, fmt.Errorf("error creating pinger: %w", err)
	}

	pgr.Count = int(count)

	slog.Debug("Pinging", slog.String("address", address), slog.Int64("amount", count))
	return p.PingWithPinger(pgr)
}

func (p *ProbingPingRunner) PingWithPinger(pgr Pinger) (PingResult, error) {
	result := PingResult{}

	ch := make(chan error, 1)
	ctxTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	go func(ch chan error) {
		err := pgr.RunWithContext(ctxTimeout)
		ch <- err
	}(ch)

	select {
	case <-ctxTimeout.Done():
		return result, fmt.Errorf("timeout reached: %w", ctxTimeout.Err())
	case err := <-ch:
		if err != nil {
			slog.Error("ping failed", slog.String("error", err.Error()))
			return result, err
		} else {
			stats := pgr.Statistics()
			result.PacketsSent = int64(stats.PacketsSent)
			result.PacketsReceived = int64(stats.PacketsRecv)
			result.AverageRttMs = stats.AvgRtt.Milliseconds()
			result.MinRttMs = stats.MinRtt.Milliseconds()
			result.MaxRttMs = stats.MaxRtt.Milliseconds()
			slog.Debug("ping success", slog.Int("Pkt sent", stats.PacketsSent), slog.Int("Pkt received", stats.PacketsRecv), slog.Float64("Pkt loss", stats.PacketLoss))
			return result, nil
		}
	}

}
