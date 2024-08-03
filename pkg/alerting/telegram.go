// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
//
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
