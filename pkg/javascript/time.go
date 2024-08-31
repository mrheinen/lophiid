package javascript

import "time"

type Time struct {
}

// Sleep allows a program to sleep the specified duration in milliseconds.
func (t Time) Sleep(msec int) {
	time.Sleep(time.Duration(msec) * time.Millisecond)
}
