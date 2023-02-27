package chatgpt_go

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBot(t *testing.T) {
	bot, err := NewChatbot(&Config{
		SessionToken: os.Getenv("session_token"),
		UserId:       "u2takey",
	})
	assert.Nil(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	prompt := "用 1000 字介绍什么是aiops"
	prevText := ""
	err = bot.Ask(ctx, prompt, "", "", func(msg *RetMessage) bool {
		if msg.Message != prompt {
			fmt.Printf(msg.Message[len(prevText):])
			prevText = msg.Message
		}
		return true
	})
	assert.Nil(t, err)
}

func TestBotNoStream(t *testing.T) {
	bot, err := NewChatbot(&Config{
		SessionToken: "",
		AccessToken:  os.Getenv("access_token"),
		UserId:       "u2takey",
	})
	assert.Nil(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	prompt := "用 1000 字介绍什么是aiops"

	msg, err := bot.AskNoStream(ctx, prompt, "", "")
	assert.Nil(t, err)
	fmt.Println(msg.Message)
	fmt.Println("--------")
}
