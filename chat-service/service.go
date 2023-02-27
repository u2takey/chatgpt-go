package main

import (
	"context"
	"sync"

	chatgpt "github.com/u2takey/chatgpt-go"
)

var botCache = sync.Map{}

func BindBot(ctx context.Context, config *BindBotRequest) *BindBotResponse {
	bot, err := chatgpt.NewChatbot(&chatgpt.Config{
		Email:        config.Email,
		Password:     config.Password,
		SessionToken: config.SessionToken,
		AccessToken:  config.AccessToken,
		UserId:       config.UserId,
		LayLoading:   true,
		Paid:         false,
	})
	if err == nil {
		botCache.Store(config.UserId, bot)
	}
	return &BindBotResponse{CommonResponse: error2CommonResponse(err)}
}

func Ask(ctx context.Context, askRequest *AskRequest) *AskResponse {
	var bot *chatgpt.Chatbot
	var err error
	if botObject, ok := botCache.Load(askRequest.UserId); ok {
		bot = botObject.(*chatgpt.Chatbot)
	} else {
		bot, err = chatgpt.NewChatbot(&chatgpt.Config{UserId: askRequest.UserId, LayLoading: true})
		if err != nil {
			return &AskResponse{CommonResponse: error2CommonResponse(err)}
		}
	}
	ret, err := bot.AskNoStream(ctx, askRequest.Prompt, askRequest.ConversationId, askRequest.ParentId)
	if err != nil {
		return &AskResponse{CommonResponse: error2CommonResponse(err)}
	}
	return &AskResponse{
		CommonResponse: CommonResponse{},
		Data: &AskData{
			ParentId:       ret.ParentId,
			Message:        ret.Message,
			ConversationId: ret.ConversationId,
			Model:          ret.Model,
		},
	}
}

func error2CommonResponse(err error) CommonResponse {
	if err != nil {
		if err1, ok := err.(*chatgpt.GptError); ok {
			return CommonResponse{Code: int(err1.Code), Message: err1.Message}
		}
		return CommonResponse{Code: 500, Message: err.Error()}
	}
	return CommonResponse{Code: 200, Message: ""}
}
