package main

type BindBotRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	SessionToken string `json:"session_token"`
	AccessToken  string `json:"access_token"`
	UserId       string `json:"user_id"`
}

type CommonResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type BindBotResponse struct {
	CommonResponse
}

type AskRequest struct {
	Prompt         string `json:"prompt"`
	ConversationId string `json:"conversation_id"`
	ParentId       string `json:"parent_id"`
	UserId         string `json:"user_id"`
}

type AskData struct {
	Message        string `json:"message"`
	ConversationId string `json:"conversation_id"`
	ParentId       string `json:"parent_id"`
	Model          string `json:"model"`
}

type AskResponse struct {
	CommonResponse
	Data *AskData `json:"data"`
}
