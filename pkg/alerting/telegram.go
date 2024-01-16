package alerting

import (
	"errors"
	"fmt"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type TelegramAlerter struct {
	bot    *tgbotapi.BotAPI
	apiKey string
	chatId int64
	debug  bool
}

func NewTelegramAlerter(apiKey string, chatId int64, debug bool) *TelegramAlerter {
	return &TelegramAlerter{
		nil, // bot
		apiKey,
		chatId,
		debug,
	}
}

func (t *TelegramAlerter) Init() error {
	bot, err := tgbotapi.NewBotAPI(t.apiKey)
	if err != nil {
		return fmt.Errorf("creating bot: %s", err)
	}

	t.bot = bot
	t.bot.Debug = t.debug
	return nil
}

// SendMessage sends a message to the configured chat channel.
func (t *TelegramAlerter) SendMessage(mesg string) error {
	if t.bot == nil {
		return errors.New("create bot first with init()")
	}

	msg := tgbotapi.NewMessage(0, mesg)
	msg.ChatID = t.chatId

	if _, err := t.bot.Send(msg); err != nil {
		return fmt.Errorf("when sending message: %s", err)
	}

	return nil
}
