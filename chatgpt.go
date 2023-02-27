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

type ErrorCode int

const (
	UnknownError   ErrorCode = 500
	ServerError    ErrorCode = 501
	RateLimitError ErrorCode = 429
	UserNotValid   ErrorCode = 401
	TokenInvalid   ErrorCode = 403
	RequestInvalid ErrorCode = 400
)

type GptError struct {
	Code    ErrorCode
	Message string
}

func (e *GptError) Error() string {
	return fmt.Sprintf("gpt error: code=%d, message=%s", e.Code, e.Message)
}

func NewGptError(code ErrorCode, message string) *GptError {
	return &GptError{Code: code, Message: message}
}

type Config struct {
	// config
	Email        string
	Password     string
	SessionToken string
	AccessToken  string
	HomePath     string
	UserId       string
	LayLoading   bool
	Paid         bool
	// history
	ConversationId      string
	ParentId            string
	ConversationQueue   []conversationInQueue
	ConversationMapping map[string]interface{}
}

type conversationInQueue struct {
	conversationId string
	parentId       string
}

type Chatbot struct {
	*Config
	session     *gorequests.Session
	cachePath   string
	sessionPath string
	configDir   string
}

func NewChatbot(config *Config) (*Chatbot, error) {
	if config.UserId == "" {
		return nil, NewGptError(RequestInvalid, "user id cannot be empty")
	}
	c := &Chatbot{Config: config}
	if err := c.makeHomePath(config); err != nil {
		return nil, err
	}
	cachedConfig := c.loadCache()
	if config != nil {
		// update config with new
		if config.Email != "" {
			cachedConfig.Email = config.Email
		}
		if config.Password != "" {
			cachedConfig.Password = config.Password
		}
		if config.SessionToken != "" {
			cachedConfig.SessionToken = config.SessionToken
		}
		if config.AccessToken != "" {
			cachedConfig.AccessToken = config.AccessToken
		}
		if config.HomePath != "" {
			cachedConfig.HomePath = config.HomePath
		}
		if config.LayLoading != cachedConfig.LayLoading {
			cachedConfig.LayLoading = config.LayLoading
		}
		if config.Paid != cachedConfig.Paid {
			cachedConfig.Paid = config.Paid
		}
	}
	c.Config = cachedConfig
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
			return NewGptError(ServerError, err.Error())
		}
		config.HomePath = home
	}
	if config.UserId == "" {
		config.UserId = "default"
	}
	c.configDir = config.HomePath + "/.config/" + config.UserId
	if err := os.MkdirAll(c.configDir, 0o777); err != nil {
		return NewGptError(ServerError, err.Error())
	}
	c.cachePath = c.configDir + "/.chatgpt_cache.json"
	if _, err := os.Stat(c.cachePath); os.IsNotExist(err) {
		// init config
		_ = ioutil.WriteFile(c.cachePath, []byte("{}"), 0o666)
	}
	c.sessionPath = c.configDir + "/.chatgpt_session"
	return nil
}

func (c *Chatbot) checkCredentials() error {
	if c.AccessToken != "" {
		c.refreshSession(c.AccessToken)
		_ = c.saveCache()
	} else if c.SessionToken != "" {
	} else if c.Email != "" && c.Password != "" {
	} else {
		return NewGptError(UserNotValid, "insufficient login details provided")
	}
	if c.AccessToken == "" {
		return c.login()
	}
	return nil
}

func (c *Chatbot) refreshSession(accessToken string) {
	c.session = gorequests.NewSession(c.sessionPath,
		gorequests.WithHeader("Accept", "text"),
		gorequests.WithHeader("Authorization", "Bearer "+accessToken),
		gorequests.WithHeader("Content-Type", "application/json"),
		gorequests.WithHeader("X-Openai-Assistant-App-Id", ""),
		gorequests.WithHeader("Connection", "close"),
		gorequests.WithHeader("Accept-Language", "en-US,en;q=0.9"),
		gorequests.WithHeader("Referer", "https://chat.openai.com/chat"))
}

type tokenJwt struct {
	Exp int64 `json:"exp"`
}

func (c *Chatbot) loadCache() *Config {
	config, err := c.readCacheConfig()
	if err != nil {
		log.Println("read cached config failed", err)
	}
	//  check token valid
	if config != nil && config.AccessToken != "" {
		accessTokenList := strings.Split(config.AccessToken, ".")
		if len(accessTokenList) > 0 {
			toPadding := len(accessTokenList[1]) % 4
			for i := 0; i < toPadding; i++ {
				accessTokenList[1] += "="
			}
			data, err := base64.StdEncoding.DecodeString(accessTokenList[1])
			if err != nil {
				log.Println("invalid cached token")
				config.AccessToken = ""
			} else {
				token := tokenJwt{}
				err = json.Unmarshal(data, &token)
				if err != nil {
					log.Println("invalid access token")
					config.AccessToken = ""
				} else if token.Exp < time.Now().Unix() {
					log.Println("access token expired")
					config.AccessToken = ""
				}
			}
		}
	}
	return config
}

func (c *Chatbot) saveCache() error {
	data, _ := json.Marshal(c.Config)
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
	if (c.Email == "" || c.Password == "") &&
		c.SessionToken == "" {
		return NewGptError(UserNotValid, "insufficient login details provided")
	}
	auth := NewAuthenticator(c.UserId).
		WithEmailPassword(c.Email, c.Password).
		WithSessionToken(c.SessionToken)
	if c.SessionToken != "" {
		err := auth.getAccessToken()
		if err != nil {
			return NewGptError(TokenInvalid, err.Error())
		}
		if auth.accessToken == "" {
			c.SessionToken = ""
			return c.login()
		}
	} else {
		err := auth.begin()
		if err != nil {
			return NewGptError(TokenInvalid, err.Error())
		}
		c.SessionToken = auth.sessionToken
		err = auth.getAccessToken()
		if err != nil {
			return NewGptError(TokenInvalid, err.Error())
		}
	}
	c.refreshSession(auth.accessToken)
	return c.saveCache()
}

func (c *Chatbot) ask(ctx context.Context, prompt string, conversationId, parentId string) (*gorequests.Request, error) {
	if conversationId == "" && parentId != "" {
		return nil, NewGptError(RequestInvalid, "conversation_id must be set once parent_id is set")
	}
	if conversationId != "" && conversationId != c.ConversationId {
		c.ParentId = ""
	}
	if conversationId == "" {
		conversationId = c.ConversationId
	}
	if parentId == "" {
		parentId = c.ParentId
	}
	if conversationId == "" && parentId == "" {
		parentId = uuid.NewString()
	}
	if conversationId != "" && parentId == "" {
		if _, ok := c.ConversationMapping[conversationId]; !ok {
			if c.LayLoading {
				history, err := c.getMsgHistory(conversationId)
				if err == nil {
					c.ConversationMapping[conversationId] = history["current_node"]
				}
			} else {
				err := c.mapConversations()
				if err != nil {
					return nil, err
				}
			}
		}
		if _, ok := c.ConversationMapping[conversationId]; ok {
			parentId = c.ConversationMapping[conversationId].(string)
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
	if c.Paid {
		data.Model = "text-davinci-002-render-paid"
	}
	c.ConversationQueue = append(c.ConversationQueue, conversationInQueue{
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
		return NewGptError(ServerError, err.Error())
	}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "Internal Server Error" {
			return NewGptError(ServerError, line)
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
				return NewGptError(RateLimitError, lineData.Detail.Str)
			}

			if lineData.Detail.Code == "invalid_api_key" {
				return NewGptError(TokenInvalid, lineData.Detail.Message)
			}
			return NewGptError(UnknownError, lineData.Detail.Message)
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
	c.ConversationMapping[conversationId] = parentId
	if parentId != "" {
		c.ParentId = parentId
	}
	if conversationId != "" {
		c.ConversationId = conversationId
	}
	_ = c.saveCache()
	return nil
}

func (c *Chatbot) AskNoStream(ctx context.Context, prompt string, conversationId, parentId string) (*RetMessage, error) {
	var ret *RetMessage
	return ret, c.Ask(ctx, prompt, conversationId, parentId, func(message *RetMessage) bool {
		ret = message
		return true
	})
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

func (c *Chatbot) getConversations(offset, limit int) ([]Conversation, error) {
	if limit == 0 {
		limit = 20
	}
	url := BASEURL + fmt.Sprintf("api/conversations?offset=%d&limit=%d", offset, limit)
	conversations := &ConversationResponse{}
	request := c.session.New("GET", url)
	err := request.Unmarshal(conversations)
	if err != nil {
		return nil, NewGptError(ServerError, err.Error())
	}
	return conversations.Items, nil

}

func checkResponse(request *gorequests.Request) error {
	statusCode, err := request.ResponseStatus()
	if err != nil {
		return NewGptError(ServerError, err.Error())
	} else if statusCode != 200 {
		return NewGptError(ErrorCode(statusCode), request.MustText())
	}
	return nil
}

func (c *Chatbot) getMsgHistory(convId string) (MsgHistory, error) {
	url := BASEURL + "api/conversation/" + convId
	history := MsgHistory{}
	request := c.session.New("GET", url)
	statusCode := request.MustResponseStatus()
	if statusCode != 200 {
		return nil, NewGptError(ErrorCode(statusCode), request.MustText())
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
		c.ConversationMapping[a.Id] = history["current_node"]
	}
	return nil
}

func (c *Chatbot) resetChat() {
	c.ConversationId = "None"
	c.ParentId = uuid.NewString()
}

func (c *Chatbot) rollbackConversation(num int) {
	for i := 0; i < num; i++ {
		if len(c.ConversationQueue) == 0 {
			return
		}
		q := c.ConversationQueue[len(c.ConversationQueue)-1]
		c.ConversationId, c.ParentId = q.conversationId, q.parentId
		c.ConversationQueue = c.ConversationQueue[0 : len(c.ConversationQueue)-1]
	}
}
