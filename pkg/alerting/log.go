package alerting

import "log/slog"

// A very simple alerter that logs the messages.
type LogAlerter struct {
}

func NewStdoutAlerter() *LogAlerter {
	return &LogAlerter{}
}

func (t *LogAlerter) Init() error {
	return nil
}

// SendMessage sends a message to the configured chat channel.
func (t *LogAlerter) SendMessage(mesg string) error {
	slog.Warn("alert", slog.String("message", mesg))
	return nil
}
