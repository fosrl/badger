package badger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	headerSetCookie        = "Set-Cookie"
	msgInternalServerError = "Internal Server Error"
)

type Config struct {
	APIBaseUrl                  string `json:"apiBaseUrl"`
	UserSessionCookieName       string `json:"userSessionCookieName"`
	ResourceSessionRequestParam string `json:"resourceSessionRequestParam"`
}

type Badger struct {
	next                        http.Handler
	name                        string
	apiBaseUrl                  string
	userSessionCookieName       string
	resourceSessionRequestParam string
}

type VerifyBody struct {
	Sessions           map[string]string `json:"sessions"`
	OriginalRequestURL string            `json:"originalRequestURL"`
	RequestScheme      *string           `json:"scheme"`
	RequestHost        *string           `json:"host"`
	RequestPath        *string           `json:"path"`
	RequestMethod      *string           `json:"method"`
	TLS                bool              `json:"tls"`
	RequestIP          *string           `json:"requestIp,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	Query              map[string]string `json:"query,omitempty"`
}

type VerifyResponse struct {
	Data struct {
		Valid           bool              `json:"valid"`
		RedirectURL     *string           `json:"redirectUrl"`
		Username        *string           `json:"username,omitempty"`
		Email           *string           `json:"email,omitempty"`
		Name            *string           `json:"name,omitempty"`
		ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	} `json:"data"`
}

type ExchangeSessionBody struct {
	RequestToken *string `json:"requestToken"`
	RequestHost  *string `json:"host"`
	RequestIP    *string `json:"requestIp,omitempty"`
}

type ExchangeSessionResponse struct {
	Data struct {
		Valid           bool              `json:"valid"`
		Cookie          *string           `json:"cookie"`
		ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	} `json:"data"`
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Badger{
		next:                        next,
		name:                        name,
		apiBaseUrl:                  config.APIBaseUrl,
		userSessionCookieName:       config.UserSessionCookieName,
		resourceSessionRequestParam: config.ResourceSessionRequestParam,
	}, nil
}

func (p *Badger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	queryValues := req.URL.Query()
	if p.handleSessionExchange(rw, req, queryValues) { // handled via redirect or error
		return
	}

	cookies := p.extractCookies(req)
	originalRequestURL := p.buildOriginalRequestURL(req, queryValues)
	p.verifySession(rw, req, originalRequestURL, cookies, queryValues)
}

// handleSessionExchange attempts to exchange a request token for a session cookie.
// Returns true if the request was fully handled (redirect or error), false to continue.
func (p *Badger) handleSessionExchange(rw http.ResponseWriter, req *http.Request, queryValues url.Values) bool {
	sessionRequestValue := queryValues.Get(p.resourceSessionRequestParam)
	if sessionRequestValue == "" {
		return false
	}

	body := ExchangeSessionBody{
		RequestToken: &sessionRequestValue,
		RequestHost:  &req.Host,
		RequestIP:    &req.RemoteAddr,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		internalServerError(rw)
		return true
	}

	url := fmt.Sprintf("%s/badger/exchange-session", p.apiBaseUrl)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		internalServerError(rw)
		return true
	}
	defer resp.Body.Close()

	var result ExchangeSessionResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		internalServerError(rw)
		return true
	}

	if result.Data.Cookie == nil || *result.Data.Cookie == "" { // continue to normal verification
		return false
	}

	rw.Header().Add(headerSetCookie, *result.Data.Cookie)
	queryValues.Del(p.resourceSessionRequestParam)

	originalRequestURL := p.buildOriginalRequestURL(req, queryValues)
	if result.Data.ResponseHeaders != nil {
		for k, v := range result.Data.ResponseHeaders {
			rw.Header().Add(k, v)
		}
	}

	fmt.Println("Got exchange token, redirecting to", originalRequestURL)
	http.Redirect(rw, req, originalRequestURL, http.StatusFound)
	return true
}

func (p *Badger) verifySession(rw http.ResponseWriter, req *http.Request, originalRequestURL string, cookies map[string]string, queryValues url.Values) {
	verifyURL := fmt.Sprintf("%s/badger/verify-session", p.apiBaseUrl)

	cookieData := VerifyBody{
		Sessions:           cookies,
		OriginalRequestURL: originalRequestURL,
		RequestScheme:      &req.URL.Scheme,
		RequestHost:        &req.Host,
		RequestPath:        &req.URL.Path,
		RequestMethod:      &req.Method,
		TLS:                req.TLS != nil,
		RequestIP:          &req.RemoteAddr,
		Headers:            p.extractHeaders(req),
		Query:              p.extractQueryParams(queryValues),
	}

	jsonData, err := json.Marshal(cookieData)
	if err != nil {
		internalServerError(rw) // TODO: redirect to error page
		return
	}

	resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		internalServerError(rw)
		return
	}
	defer resp.Body.Close()

	for _, setCookie := range resp.Header[headerSetCookie] {
		rw.Header().Add(headerSetCookie, setCookie)
	}

	if resp.StatusCode != http.StatusOK {
		internalServerError(rw)
		return
	}

	var result VerifyResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		internalServerError(rw)
		return
	}

	if result.Data.ResponseHeaders != nil {
		for k, v := range result.Data.ResponseHeaders {
			rw.Header().Add(k, v)
		}
	}

	if result.Data.RedirectURL != nil && *result.Data.RedirectURL != "" {
		fmt.Println("Badger: Redirecting to", *result.Data.RedirectURL)
		http.Redirect(rw, req, *result.Data.RedirectURL, http.StatusFound)
		return
	}

	if !result.Data.Valid {
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Attach identity headers
	if result.Data.Username != nil {
		req.Header.Add("Remote-User", *result.Data.Username)
	}
	if result.Data.Email != nil {
		req.Header.Add("Remote-Email", *result.Data.Email)
	}
	if result.Data.Name != nil {
		req.Header.Add("Remote-Name", *result.Data.Name)
	}

	fmt.Println("Badger: Valid session")
	p.next.ServeHTTP(rw, req)
}

func (p *Badger) buildOriginalRequestURL(req *http.Request, queryValues url.Values) string {
	cleanedQuery := queryValues.Encode()
	base := fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.Path)
	if cleanedQuery == "" {
		return base
	}
	return fmt.Sprintf("%s?%s", base, cleanedQuery)
}

func (p *Badger) extractHeaders(req *http.Request) map[string]string {
	result := make(map[string]string)
	for name, values := range req.Header {
		if len(values) > 0 {
			result[name] = values[0]
		}
	}
	return result
}

func (p *Badger) extractQueryParams(values url.Values) map[string]string {
	result := make(map[string]string)
	for k, v := range values {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result
}

func internalServerError(rw http.ResponseWriter) {
	http.Error(rw, msgInternalServerError, http.StatusInternalServerError)
}

func (p *Badger) extractCookies(req *http.Request) map[string]string {
	cookies := make(map[string]string)
	isSecureRequest := req.TLS != nil

	for _, cookie := range req.Cookies() {
		if strings.HasPrefix(cookie.Name, p.userSessionCookieName) {
			if cookie.Secure && !isSecureRequest {
				continue
			}
			cookies[cookie.Name] = cookie.Value
		}
	}

	return cookies
}

func (p *Badger) getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}
