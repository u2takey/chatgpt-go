package chatgpt_go

import "encoding/json"

type Content struct {
	ContentType string   `json:"content_type"`
	Parts       []string `json:"parts"`
}

type MessageMeta struct {
	ModelSlug string `json:"model_slug"`
}
type Message struct {
	Id       string       `json:"id"`
	Role     string       `json:"role,omitempty"`
	Content  *Content     `json:"content,omitempty"`
	MetaData *MessageMeta `json:"meta_data,omitempty"`
}

type ConversationData struct {
	Action          string    `json:"action"`
	Messages        []Message `json:"messages"`
	ConversationId  string    `json:"conversation_id,omitempty"`
	ParentMessageId string    `json:"parent_message_id,omitempty"`
	Model           string    `json:"model"`
}

type RetMessage struct {
	Message        string `json:"message"`
	ConversationId string `json:"conversation_id"`
	ParentId       string `json:"parent_id"`
	Model          string `json:"model"`
}

type LineWithContent struct {
	Message        Message `json:"message"`
	Detail         Detail  `json:"detail"`
	ConversationId string  `json:"conversation_id"`
}
type Detail struct {
	Str     string `json:"str"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (d *Detail) UnmarshalJSON(data []byte) error {
	if len(data) > 1 && data[0] == '{' {
		a := struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}{}
		err := json.Unmarshal(data, &a)
		d.Code = a.Code
		d.Message = a.Message
		return err
	}
	if len(data) >= 2 {
		d.Str = string(data[1 : len(data)-1])
	}
	return nil
}

type ConversationResponse struct {
	Items []Conversation `json:"items"`
}

type Conversation struct {
	Id string `json:"id"`
}

type MsgHistory map[string]interface{}
