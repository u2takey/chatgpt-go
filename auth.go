package chatgpt_go

import (
	"fmt"
	netUrl "net/url"
	"regexp"
	"strings"

	"github.com/chyroc/gorequests"
)

type AuthError struct {
	Code    int
	Message string
}

type Authenticator struct {
	emailAddress string
	password     string
	proxy        string
	userAgent    string
	sessionToken string
	accessToken  string
	session      *gorequests.Session
}

// NewAuthenticator OpenAI Authentication Reverse Engineered
func NewAuthenticator(userId string) *Authenticator {
	a := &Authenticator{
		userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
		session:   gorequests.NewSession("/tmp/" + userId),
	}
	return a
}

func (a *Authenticator) WithEmailPassword(emailAddress, password string) *Authenticator {
	a.emailAddress, a.password = emailAddress, password
	return a
}

func (a *Authenticator) WithProxy(proxy string) *Authenticator {
	a.proxy = proxy
	return a
}

func (a *Authenticator) WithSessionToken(token string) *Authenticator {
	a.sessionToken = token
	return a
}

func (a *Authenticator) WithAccessToken(token string) *Authenticator {
	a.accessToken = token
	return a
}

func urlEncode(s string) string {
	return netUrl.QueryEscape(s)
}

type TokenResp struct {
	CsrfToken string `json:"csrfToken"`
}

func (a *Authenticator) begin() error {
	var url = "https://explorer.api.openai.com/api/auth/csrf"
	headers := map[string]string{
		"Host":            "explorer.api.openai.com",
		"Accept":          "*/*",
		"Connection":      "keep-alive",
		"User-Agent":      a.userAgent,
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
		"Referer":         "https://explorer.api.openai.com/auth/login",
		"Accept-Encoding": "gzip, funclate, br",
	}
	resp := &TokenResp{}
	err := a.session.New("GET", url).WithHeaders(headers).Unmarshal(resp)
	if err != nil {
		return err
	}
	return a.partOne(resp.CsrfToken)
}

type PartOneResponse struct {
	Url string `json:"url"`
}

func (a *Authenticator) partOne(token string) error {

	var url = "https://explorer.api.openai.com/api/auth/signin/auth0?prompt=login"
	var payload = "callbackUrl=%2F&json=true&csrfToken=" + token
	headers := map[string]string{
		"Host":            "explorer.api.openai.com",
		"User-Agent":      a.userAgent,
		"Content-Type":    "application/x-www-form-urlencoded",
		"Accept":          "*/*",
		"Sec-Gpc":         "1",
		"Accept-Language": "en-US,en;q=0.8",
		"Origin":          "https://explorer.api.openai.com",
		"Sec-Fetch-Site":  "same-origin",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Dest":  "empty",
		"Referer":         "https://explorer.api.openai.com/auth/login",
		"Accept-Encoding": "gzip, funclate",
	}
	resp := &PartOneResponse{}
	request := a.session.New("POST", url).WithHeaders(headers).WithBody(payload)
	err := request.Unmarshal(resp)
	if err != nil {
		return err
	}
	statusCode := request.MustResponseStatus()
	if statusCode == 200 {
		if strings.Contains(resp.Url, "error") {
			return fmt.Errorf("code: %d, message: %s", request.MustResponseStatus(), "You have been rate limited. Please try again later.")
		}
		return a.partTwo(resp.Url)
	} else {
		return fmt.Errorf("code: %d, message: %s", request.MustResponseStatus(), request.MustText())
	}
}

var stateRegex = regexp.MustCompile("state=(.*)")

func (a *Authenticator) partTwo(url string) error {

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      a.userAgent,
		"Accept-Language": "en-US,en;q=0.9",
		"Referer":         "https://explorer.api.openai.com/",
	}
	request := a.session.New("GET", url).WithHeaders(headers)
	data, err := request.Text()
	if err != nil {
		return err
	}
	statusCode := request.MustResponseStatus()
	if statusCode == 302 || statusCode == 200 {
		l := stateRegex.FindStringSubmatch(data)
		if len(l) == 0 {
			return fmt.Errorf("state not found")
		}
		ll := strings.Split(l[0], "\"")
		if len(ll) == 0 {
			return fmt.Errorf("state not found")
		}
		return a.partThree(ll[0])
	}
	return fmt.Errorf("code: %d, message: %s", statusCode, data)
}

func (a *Authenticator) partThree(state string) error {
	var url = "https://auth0.openai.com/u/login/identifier?state=" + state

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      a.userAgent,
		"Accept-Language": "en-US,en;q=0.9",
		"Referer":         "https://explorer.api.openai.com/",
	}

	request := a.session.New("GET", url).WithHeaders(headers)
	data, err := request.Text()
	if err != nil {
		return err
	}
	statusCode := request.MustResponseStatus()
	if statusCode == 200 {
		return a.partFour(state)
	}
	return fmt.Errorf("code: %d, message: %s", statusCode, data)
}

func (a *Authenticator) partFour(state string) error {
	url := "https://auth0.openai.com/u/login/identifier?state=" + state

	payload := fmt.Sprintf("state=%s&username=%s&js-available=false&webauthn-available=true&is"+
		"-brave=false&webauthn-platform-available=true&action=funcault ", state, urlEncode(a.emailAddress))

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Origin":          "https://auth0.openai.com",
		"Connection":      "keep-alive",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"User-Agent":      a.userAgent,
		"Referer":         "https://auth0.openai.com/u/login/identifier?state=" + state,
		"Accept-Language": "en-US,en;q=0.9",
		"Content-Type":    "application/x-www-form-urlencoded",
	}

	request := a.session.New("POST", url).WithHeaders(headers).WithBody(payload)
	data, err := request.Text()
	if err != nil {
		return err
	}
	statusCode := request.MustResponseStatus()
	if statusCode == 302 || statusCode == 200 {
		return a.partFive(state)
	}

	return fmt.Errorf("code: %d, message: %s", statusCode, data)
}

func (a *Authenticator) partFive(state string) error {

	url := "https://auth0.openai.com/u/login/password?state=" + state

	payload := fmt.Sprintf("state=%s&username=%s&password=%s&action=funcault", state, urlEncode(a.emailAddress), urlEncode(a.password))
	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Origin":          "https://auth0.openai.com",
		"Connection":      "keep-alive",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"User-Agent":      a.userAgent,
		"Referer":         "https://auth0.openai.com/u/login/password?state=" + state,
		"Accept-Language": "en-US,en;q=0.9",
		"Content-Type":    "application/x-www-form-urlencoded",
	}
	request := a.session.New("POST", url).WithHeaders(headers).WithBody(payload).WithRedirect(false)
	data, err := request.Text()
	if err != nil {
		return err
	}
	statusCode := request.MustResponseStatus()
	if statusCode == 302 || statusCode == 200 {
		l := stateRegex.FindStringSubmatch(data)
		if len(l) == 0 {
			return fmt.Errorf("state not found")
		}
		ll := strings.Split(l[0], "\"")
		if len(ll) == 0 {
			return fmt.Errorf("state not found")
		}
		return a.partSix(state, ll[0])
	}
	return fmt.Errorf("code: %d, message: %s", statusCode, data)
}

func (a *Authenticator) partSix(oldState, newState string) error {

	url := "https://auth0.openai.com/authorize/resume?state=" + newState
	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      a.userAgent,
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
		"Referer":         "https://auth0.openai.com/u/login/password?state=" + oldState,
	}

	request := a.session.New("GET", url).WithHeaders(headers).WithRedirect(false)
	data, err := request.Text()
	if err != nil {
		return err
	}
	statusCode := request.MustResponseStatus()
	if statusCode == 302 {
		return a.partSeven(request.MustResponseHeaderByKey("location"), url)
	}
	return fmt.Errorf("code: %d, message: %s", statusCode, data)
}

func (a *Authenticator) partSeven(redirectUrl, previousUrl string) error {
	var url = redirectUrl
	headers := map[string]string{
		"Host":            "explorer.api.openai.com",
		"Accept":          "application/json",
		"Connection":      "keep-alive",
		"User-Agent":      a.userAgent,
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
		"Referer":         previousUrl,
	}
	request := a.session.New("GET", url).WithHeaders(headers).WithRedirect(false)
	data, err := request.Text()
	if err != nil {
		return err
	}
	resp := request.MustResponse()
	statusCode := request.MustResponseStatus()
	if statusCode == 302 {
		for _, v := range resp.Cookies() {
			if v.Name == "__Secure-next-auth.session-token" {
				a.sessionToken = v.Value
			}
		}
		return a.getAccessToken()
	}
	return fmt.Errorf("code: %d, message: %s", statusCode, data)
}

type TokenResponse struct {
	AccessToken string `json:"accessToken"`
}

func (a *Authenticator) getAccessToken() error {
	request := a.session.New("GET", "https://explorer.api.openai.com/api/auth/session").
		WithHeader("cookie", "__Secure-next-auth.session-token="+a.sessionToken)
	resp := &TokenResponse{}
	err := request.Unmarshal(resp)
	if err != nil {
		return err
	}
	statusCode := request.MustResponseStatus()
	if statusCode == 200 {
		a.accessToken = resp.AccessToken
		return nil
	} else {
		return fmt.Errorf("code: %d, message: %s", statusCode, request.MustText())
	}
}
