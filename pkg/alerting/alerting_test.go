package alerting

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

type FakeAlerter struct {
	initError        error
	messageBuffer    []string
	sendMessageError error
}

func (f *FakeAlerter) Init() error {
	return f.initError
}

func (f *FakeAlerter) SendMessage(mesg string) error {
	f.messageBuffer = append(f.messageBuffer, mesg)
	return f.sendMessageError
}

func TestSendMessageOk(t *testing.T) {
	fa := FakeAlerter{
		initError:        nil,
		sendMessageError: nil,
	}

	am := NewAlertManager(time.Minute)
	if err := am.AddAlerter(&fa); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	msg := "test"
	am.SendMessage(msg)
	if len(fa.messageBuffer) != 1 {
		t.Errorf("expected 1, got %d", len(fa.messageBuffer))
	}

	if fa.messageBuffer[0] != msg {
		t.Errorf("expected %s, got %s", msg, fa.messageBuffer[0])
	}
}

func getRandomString(strSize int) string {
	charset := "abcdefghijklmnopqrstuvwxyz"

	var sb strings.Builder
	for i := 0; i < strSize; i++ {
		sb.WriteByte(charset[rand.Intn(len(charset))])
	}

	return sb.String()
}

func TestSendBufferedMessageOk(t *testing.T) {
	fa := FakeAlerter{
		initError:        nil,
		sendMessageError: nil,
	}

	am := NewAlertManager(time.Minute)
	if err := am.AddAlerter(&fa); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	msg1 := "test 1"
	msg2 := "test 2"
	am.SendBufferedMessage(msg1)
	am.SendBufferedMessage(msg2)
	am.EmptyBuffer()

	if len(fa.messageBuffer) != 1 {
		t.Errorf("expected 1, got %d", len(fa.messageBuffer))
	}

	expectedMsg1 := fmt.Sprintf("%s\n%s", msg1, msg2)
	expectedMsg2 := fmt.Sprintf("%s\n%s", msg2, msg1)
	if fa.messageBuffer[0] != expectedMsg1 && fa.messageBuffer[0] != expectedMsg2 {
		t.Errorf("got '%s'", fa.messageBuffer[0])
	}

	// Next check if the maximum size is respected.
	fa.messageBuffer = []string{}
	msg1 = getRandomString(4000)
	msg2 = getRandomString(4000)

	am.SendBufferedMessage(msg1)
	am.SendBufferedMessage(msg2)
	am.EmptyBuffer()

	if len(fa.messageBuffer) != 2 {
		t.Errorf("expected 2, got %d (%v)", len(fa.messageBuffer), fa.messageBuffer)
	}
}
