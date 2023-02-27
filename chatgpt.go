package chatgpt_go

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/chyroc/gorequests"
	"github.com/google/uuid"
)

var (
	BASEURL = getEnvWithDefault("CHATGPT_BASE_URL", "https://chatgpt.duti.tech/")
)

// GptError
//-1: User error
// 0: Unknown error
// 1: Server error
// 2: Rate limit error
// 3: Invalid request error
// 4: Expired access token error
// 5: Invalid access token error
// 6: Insufficient login details
type GptError struct {
	Code    int
	Message string
}

func (e *GptError) Error() string {
	return fmt.Sprintf("gpt error: code=%d, message=%s", e.Code, e.Message)
}

type Config struct {
	Email        string
	Password     string
	SessionToken string
	AccessToken  string
	HomePath     string
	UserId       string
	LayLoading   bool
	Paid         bool
}

type conversationInQueue struct {
	conversationId string
	parentId       string
}

type Chatbot struct {
	config              *Config
	conversationId      string
	parentId            string
	conversationQueue   []conversationInQueue
	conversationMapping map[string]interface{}
	configDir           string
	session             *gorequests.Session
	cachePath           string
	sessionPath         string
}

func NewChatbot(config *Config) (*Chatbot, error) {
	if config.UserId == "" {
		return nil, &GptError{Code: -1, Message: "user id cannot be empty"}
	}
	c := &Chatbot{config: config, conversationMapping: map[string]interface{}{}}
	if err := c.makeHomePath(config); err != nil {
		return nil, err
	}

	cachedToken, err := c.getCachedAccessToken()
	if err == nil && cachedToken != "" && c.config.AccessToken == "" {
		c.config.AccessToken = cachedToken
	}
	return c, c.checkCredentials()
}

func (c *Chatbot) WithSession(session *gorequests.Session) *Chatbot {
	c.session = session
	return c
}

func (c *Chatbot) makeHomePath(config *Config) error {
	if config.HomePath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		config.HomePath = home
	}
	if config.UserId == "" {
		config.UserId = "default"
	}
	c.configDir = config.HomePath + "/.config/" + config.UserId
	if err := os.MkdirAll(c.configDir, 0o777); err != nil {
		return err
	}
	c.cachePath = c.configDir + "/.chatgpt_cache.json"
	if _, err := os.Stat(c.cachePath); os.IsNotExist(err) {
		_ = ioutil.WriteFile(c.cachePath, []byte("{}"), 0o666)
	}
	c.sessionPath = c.configDir + "/.chatgpt_session"
	return nil
}

func (c *Chatbot) checkCredentials() error {
	if c.config.AccessToken != "" {
		_ = c.refreshHeaders(c.config.AccessToken)
	} else if c.config.SessionToken != "" {
	} else if c.config.Email != "" && c.config.Password != "" {
	} else {
		return &GptError{Code: -1, Message: "Insufficient login details provided!"}
	}
	if c.config.AccessToken == "" {
		return c.login()
	}
	return nil
}

func (c *Chatbot) refreshHeaders(accessToken string) error {
	c.session = gorequests.NewSession(c.sessionPath,
		gorequests.WithHeader("Accept", "text"),
		gorequests.WithHeader("Authorization", "Bearer "+accessToken),
		gorequests.WithHeader("Content-Type", "application/json"),
		gorequests.WithHeader("X-Openai-Assistant-App-Id", ""),
		gorequests.WithHeader("Connection", "close"),
		gorequests.WithHeader("Accept-Language", "en-US,en;q=0.9"),
		gorequests.WithHeader("Referer", "https://chat.openai.com/chat"))
	c.config.AccessToken = accessToken
	return c.cacheAccessToken()
}

type tokenJwt struct {
	Exp int64 `json:"exp"`
}

func (c *Chatbot) getCachedAccessToken() (string, error) {
	config, err := c.readCacheConfig()
	if err != nil {
		log.Println("read cached token failed", err)
	}
	//  Parse access_token as JWT
	if config.AccessToken != "" {
		accessTokenList := strings.Split(config.AccessToken, ".")
		if len(accessTokenList) > 0 {
			toPadding := len(accessTokenList[1]) % 4
			for i := 0; i < toPadding; i++ {
				accessTokenList[1] += "="
			}
			data, err := base64.StdEncoding.DecodeString(accessTokenList[1])
			if err != nil {
				return "", &GptError{Code: 5, Message: "Invalid access token"}
			}
			token := tokenJwt{}
			err = json.Unmarshal(data, &token)
			if err != nil {
				return "", &GptError{Code: 5, Message: "Invalid access token"}
			}
			if token.Exp < time.Now().Unix() {
				return "", &GptError{Code: 4, Message: "Access token expired"}
			}
		} else {
			return "", &GptError{Code: 5, Message: "Invalid access token"}
		}
	}
	return config.AccessToken, nil
}

func (c *Chatbot) cacheAccessToken() error {
	return c.writeCache()
}

func (c *Chatbot) writeCache() error {
	data, _ := json.Marshal(c.config)
	return ioutil.WriteFile(c.cachePath, data, 0o666)
}

func (c *Chatbot) readCacheConfig() (*Config, error) {
	ret := &Config{}
	data, err := ioutil.ReadFile(c.cachePath)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, ret)
	return ret, err
}

func (c *Chatbot) login() error {
	if (c.config.Email == "" || c.config.Password == "") &&
		c.config.SessionToken == "" {
		return &GptError{Code: 6, Message: "Insufficient login details provided!"}
	}
	auth := NewAuthenticator(c.config.UserId).
		WithEmailPassword(c.config.Email, c.config.Password).
		WithSessionToken(c.config.SessionToken)
	if c.config.SessionToken != "" {
		err := auth.getAccessToken()
		if err != nil {
			return err
		}
		if auth.accessToken == "" {
			c.config.SessionToken = ""
			return c.login()
		}
	} else {
		err := auth.begin()
		if err != nil {
			return err
		}
		c.config.SessionToken = auth.sessionToken
		err = auth.getAccessToken()
		if err != nil {
			return err
		}
	}
	return c.refreshHeaders(auth.accessToken)
}

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

func (c *Chatbot) ask(ctx context.Context, prompt string, conversationId, parentId string) (*gorequests.Request, error) {
	if conversationId == "" && parentId != "" {
		return nil, &GptError{Code: -1, Message: "conversation_id must be set once parent_id is set"}
	}
	if conversationId != "" && conversationId != c.conversationId {
		c.parentId = ""
	}
	if conversationId == "" {
		conversationId = c.conversationId
	}
	if parentId == "" {
		parentId = c.parentId
	}
	if conversationId == "" && parentId == "" {
		parentId = uuid.NewString()
	}
	if conversationId != "" && parentId == "" {
		if _, ok := c.conversationMapping[conversationId]; !ok {
			if c.config.LayLoading {
				history, err := c.getMsgHistory(conversationId)
				if err == nil {
					c.conversationMapping[conversationId] = history["current_node"]
				}
			} else {
				err := c.mapConversations()
				if err != nil {
					return nil, err
				}
			}
		}
		if _, ok := c.conversationMapping[conversationId]; ok {
			parentId = c.conversationMapping[conversationId].(string)
		} else {
			conversationId = ""
			parentId = uuid.NewString()
		}
	}

	data := &ConversationData{
		Action:          "next",
		Messages:        []Message{{Id: uuid.NewString(), Role: "user", Content: &Content{ContentType: "text", Parts: []string{prompt}}}},
		ConversationId:  conversationId,
		ParentMessageId: parentId,
		Model:           "text-davinci-002-render-sha",
	}
	if c.config.Paid {
		data.Model = "text-davinci-002-render-paid"
	}
	c.conversationQueue = append(c.conversationQueue, conversationInQueue{
		conversationId: conversationId,
		parentId:       parentId,
	})

	request := c.session.New("POST", BASEURL+"api/conversation").WithBody(data).WithContext(ctx)
	err := checkResponse(request)
	return request, err
}

func (c *Chatbot) Ask(ctx context.Context, prompt string, conversationId, parentId string, handle func(message *RetMessage) bool) error {
	request, err := c.ask(ctx, prompt, conversationId, parentId)
	if err != nil {
		return err
	}
	resp, err := request.Response()
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "Internal Server Error" {
			return &GptError{Code: -1, Message: line}
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			line = line[6:]
		}
		if line == "[DONE]" {
			break
		}
		lineData := &LineWithContent{}
		err = json.Unmarshal([]byte(line), lineData)
		if err != nil {
			continue
		}
		if !c.checkFields(lineData) {
			if lineData.Detail.Str == "Too many requests in 1 hour. Try again later." {
				return &GptError{Code: 2, Message: lineData.Detail.Str}
			}

			if lineData.Detail.Code == "invalid_api_key" {
				return &GptError{Code: 3, Message: lineData.Detail.Message}
			}
			return &GptError{Code: -1, Message: lineData.Detail.Message}
		}
		message, model := "", ""
		if len(lineData.Message.Content.Parts) > 0 {
			message = lineData.Message.Content.Parts[0]
		}
		conversationId = lineData.ConversationId
		parentId = lineData.Message.Id
		if lineData.Message.MetaData != nil && lineData.Message.MetaData.ModelSlug != "" {
			model = lineData.Message.MetaData.ModelSlug
		}
		if !handle(&RetMessage{
			Message:        message,
			ConversationId: conversationId,
			ParentId:       parentId,
			Model:          model,
		}) {
			break
		}
	}
	c.conversationMapping[conversationId] = parentId
	if parentId != "" {
		c.parentId = parentId
	}
	if conversationId != "" {
		c.conversationId = conversationId
	}
	return nil
}

func (c *Chatbot) AskNoStream(ctx context.Context, prompt string, conversationId, parentId string) (*RetMessage, error) {
	var ret *RetMessage
	return ret, c.Ask(ctx, prompt, conversationId, parentId, func(message *RetMessage) bool {
		ret = message
		return true
	})
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

func (c *Chatbot) checkFields(data *LineWithContent) bool {
	if data == nil {
		return false
	}
	if data.Message.Content == nil {
		return false
	}
	return true
}

type ConversationResponse struct {
	Items []Conversation `json:"items"`
}

type Conversation struct {
	Id string `json:"id"`
}

func (c *Chatbot) getConversations(offset, limit int) ([]Conversation, error) {
	if limit == 0 {
		limit = 20
	}
	url := BASEURL + fmt.Sprintf("api/conversations?offset=%d&limit=%d", offset, limit)
	conversations := &ConversationResponse{}
	request := c.session.New("GET", url)
	err := request.Unmarshal(conversations)
	return conversations.Items, err

}

func checkResponse(request *gorequests.Request) error {
	statusCode, err := request.ResponseStatus()
	if err != nil {
		return err
	} else if statusCode != 200 {
		return &GptError{Code: statusCode, Message: request.MustText()}
	}
	return nil
}

type MsgHistory map[string]interface{}

func (c *Chatbot) getMsgHistory(convId string) (MsgHistory, error) {
	url := BASEURL + "api/conversation/" + convId
	history := MsgHistory{}
	request := c.session.New("GET", url)
	statusCode := request.MustResponseStatus()
	if statusCode != 200 {
		return nil, &GptError{Code: statusCode, Message: request.MustText()}
	}
	err := request.Unmarshal(&history)
	return history, err
}

func (c *Chatbot) genTitle(convId, messageId string) error {
	request := c.session.New("POST", BASEURL+"api/conversation/gen_title/"+convId).WithBody(map[string]string{
		"message_id": messageId,
		"model":      "text-davinci-002-render",
	})
	return checkResponse(request)
}

func (c *Chatbot) changeTitle(convId, title string) error {
	request := c.session.New("PATCH", BASEURL+"api/conversation/"+convId).WithBody(map[string]string{
		"title": title,
	})
	return checkResponse(request)
}

func (c *Chatbot) deleteConversation(convId string) error {
	request := c.session.New("PATCH", BASEURL+"api/conversation/"+convId).WithBody(map[string]interface{}{
		"is_visible": false,
	})
	return checkResponse(request)
}

func (c *Chatbot) clearConversations() error {
	request := c.session.New("PATCH", BASEURL+"api/conversations").WithBody(map[string]interface{}{
		"is_visible": false,
	})
	return checkResponse(request)
}

func (c *Chatbot) mapConversations() error {
	conversations, err := c.getConversations(0, 20)
	if err != nil {
		return err
	}
	var histories []MsgHistory
	for _, a := range conversations {
		history, err := c.getMsgHistory(a.Id)
		if err != nil {
			continue
		}
		histories = append(histories, history)
		c.conversationMapping[a.Id] = history["current_node"]
	}
	return nil
}

func (c *Chatbot) resetChat() {
	c.conversationId = "None"
	c.parentId = uuid.NewString()
}

func (c *Chatbot) rollbackConversation(num int) {
	for i := 0; i < num; i++ {
		if len(c.conversationQueue) == 0 {
			return
		}
		q := c.conversationQueue[len(c.conversationQueue)-1]
		c.conversationId, c.parentId = q.conversationId, q.parentId
		c.conversationQueue = c.conversationQueue[0 : len(c.conversationQueue)-1]
	}
}
