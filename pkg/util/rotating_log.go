package util

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// DailyRotatingLogWriter writes logs to a file that is rotated daily.
// The file name will be <basePath>.<date>.
type DailyRotatingLogWriter struct {
	basePath     string
	currentFile  *os.File
	currentYear  int
	currentMonth time.Month
	currentDay   int
	mu           sync.Mutex
	nowFunc      func() time.Time
}

// NewDailyRotatingLogWriter creates a new DailyRotatingLogWriter and opens the initial log file.
func NewDailyRotatingLogWriter(basePath string) (*DailyRotatingLogWriter, error) {
	w := &DailyRotatingLogWriter{
		basePath: basePath,
		nowFunc:  time.Now,
	}

	// Initialize the file immediately to catch permission errors early
	if err := w.rotate(w.nowFunc()); err != nil {
		return nil, err
	}

	return w, nil
}

// Write writes the data to the current log file, rotating if the date has changed.
func (w *DailyRotatingLogWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := w.nowFunc()
	y, m, d := now.Date()

	if w.currentFile == nil || y != w.currentYear || m != w.currentMonth || d != w.currentDay {
		if err := w.rotate(now); err != nil {
			return 0, err
		}
	}

	return w.currentFile.Write(p)
}

// rotate closes the current file and opens a new one for the given date.
// This method must be called with the lock held.
func (w *DailyRotatingLogWriter) rotate(t time.Time) error {
	if w.currentFile != nil {
		// Attempt to close, but ignore error as we are moving to a new file anyway.
		// We could log it to stderr if strictly needed.
		_ = w.currentFile.Close()
	}

	dateStr := t.Format("2006-01-02")
	filename := fmt.Sprintf("%s.%s", w.basePath, dateStr)
	
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	w.currentFile = f
	w.currentYear, w.currentMonth, w.currentDay = t.Date()
	
	return nil
}

// Close closes the underlying log file.
func (w *DailyRotatingLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.currentFile != nil {
		return w.currentFile.Close()
	}
	return nil
}

// Ensure DailyRotatingLogWriter implements io.WriteCloser
var _ io.WriteCloser = (*DailyRotatingLogWriter)(nil)
