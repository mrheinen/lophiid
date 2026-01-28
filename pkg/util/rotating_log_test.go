package util

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDailyRotatingLogWriter(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rotating_log_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	basePath := filepath.Join(tempDir, "test.log")

	// Create the writer
	w, err := NewDailyRotatingLogWriter(basePath)
	require.NoError(t, err)
	defer w.Close()

	// Write something for "today"
	_, err = w.Write([]byte("log line 1\n"))
	require.NoError(t, err)

	now := time.Now()
	dateStr := now.Format("2006-01-02")
	expectedFile1 := fmt.Sprintf("%s.%s", basePath, dateStr)

	// Verify file exists and content
	content, err := os.ReadFile(expectedFile1)
	require.NoError(t, err)
	assert.Equal(t, "log line 1\n", string(content))

	// Override nowFunc to control time
	currentMockTime := time.Date(2023, 10, 26, 10, 0, 0, 0, time.UTC)
	w.nowFunc = func() time.Time {
		return currentMockTime
	}

	
	// Let's reset the internal state to match our "start" time
	w.mu.Lock()
	w.currentYear, w.currentMonth, w.currentDay = currentMockTime.Date()
	// We also need to close the file opened by New and open the one for our mock start time to be consistent
	w.currentFile.Close()
	startFile := fmt.Sprintf("%s.2023-10-26", basePath)
	f, err := os.OpenFile(startFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	w.currentFile = f
	w.mu.Unlock()

	// Write for day 1
	_, err = w.Write([]byte("day 1 log\n"))
	require.NoError(t, err)

	content1, err := os.ReadFile(startFile)
	require.NoError(t, err)
	assert.Equal(t, "day 1 log\n", string(content1))

	// Move to the next day
	currentMockTime = currentMockTime.AddDate(0, 0, 1) // 2023-10-27

	// Write for day 2
	_, err = w.Write([]byte("day 2 log\n"))
	require.NoError(t, err)

	// Check day 1 file is unchanged
	content1After, err := os.ReadFile(startFile)
	require.NoError(t, err)
	assert.Equal(t, "day 1 log\n", string(content1After))

	// Check day 2 file exists and has content
	nextDayFile := fmt.Sprintf("%s.2023-10-27", basePath)
	content2, err := os.ReadFile(nextDayFile)
	require.NoError(t, err)
	assert.Equal(t, "day 2 log\n", string(content2))
}
