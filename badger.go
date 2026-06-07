package badger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fosrl/badger/ips"
	"github.com/fosrl/badger/version"
)

const (
	errInternalServer  = "Internal Server Error"
	errUnauthorized    = "Unauthorized"
	headerSetCookie    = "Set-Cookie"
	headerRemoteUserID = "Remote-User-Id"
	headerRemoteUser   = "Remote-User"
	headerRemoteEmail  = "Remote-Email"
	headerRemoteName   = "Remote-Name"
	headerRemoteRole   = "Remote-Role"
	headerContentType  = "Content-Type"
)

type Config struct {
	APIBaseURL                  string   `json:"apiBaseUrl,omitempty"`
	UserSessionCookieName       string   `json:"userSessionCookieName,omitempty"`
	ResourceSessionRequestParam string   `json:"resourceSessionRequestParam,omitempty"`
	AccessTokenQueryParam       string   `json:"accessTokenQueryParam,omitempty"`
	AccessTokenIDHeader         string   `json:"accessTokenIdHeader,omitempty"`
	AccessTokenHeader           string   `json:"accessTokenHeader,omitempty"`
	DisableForwardAuth          bool     `json:"disableForwardAuth,omitempty"`
	TrustIP                     []string `json:"trustip,omitempty"`
	DisableDefaultCFIPs         bool     `json:"disableDefaultCFIPs,omitempty"`
	CustomIPHeader              string   `json:"customIPHeader,omitempty"`
}

const (
	xRealIP        = "X-Real-Ip"
	xForwardFor    = "X-Forwarded-For"
	xForwardProto  = "X-Forwarded-Proto"
	cfConnectingIP = "CF-Connecting-IP"
	cfVisitor      = "CF-Visitor"
)

type Badger struct {
	next                        http.Handler
	name                        string
	apiBaseURL                  string
	userSessionCookieName       string
	resourceSessionRequestParam string
	accessTokenQueryParam       string
	accessTokenIDHeader         string
	accessTokenHeader           string
	disableForwardAuth          bool
	trustIP                     []*net.IPNet
	customIPHeader              string
	httpClient                  *http.Client
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
	BadgerVersion      string            `json:"badgerVersion,omitempty"`
}

type VerifyResponseData struct {
	HeaderAuthChallenged bool              `json:"headerAuthChallenged"`
	Valid                bool              `json:"valid"`
	RedirectURL          *string           `json:"redirectUrl"`
	UserID               *string           `json:"userId,omitempty"`
	DontStripSession     bool              `json:"dontStripSession,omitempty"`
	Username             *string           `json:"username,omitempty"`
	Email                *string           `json:"email,omitempty"`
	Name                 *string           `json:"name,omitempty"`
	Role                 *string           `json:"role,omitempty"`
	ResponseHeaders      map[string]string `json:"responseHeaders,omitempty"`
	PangolinVersion      *string           `json:"pangolinVersion,omitempty"`
}

type VerifyResponse struct {
	Data VerifyResponseData `json:"data"`
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

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	badger := &Badger{
		next:                        next,
		name:                        name,
		apiBaseURL:                  config.APIBaseURL,
		userSessionCookieName:       config.UserSessionCookieName,
		resourceSessionRequestParam: config.ResourceSessionRequestParam,
		accessTokenQueryParam:       config.AccessTokenQueryParam,
		accessTokenIDHeader:         config.AccessTokenIDHeader,
		accessTokenHeader:           config.AccessTokenHeader,
		disableForwardAuth:          config.DisableForwardAuth,
		customIPHeader:              config.CustomIPHeader,
		httpClient:                  &http.Client{Timeout: 10 * time.Second},
	}

	if err := badger.parseTrustedIPs(config.TrustIP, config.DisableDefaultCFIPs); err != nil {
		return nil, err
	}

	return badger, nil
}

// validateConfig checks required fields when forward auth is enabled.
func validateConfig(config *Config) error {
	if config.DisableForwardAuth {
		return nil
	}
	if config.APIBaseURL == "" {
		return fmt.Errorf("apiBaseURL is required when forward auth is enabled")
	}
	if config.UserSessionCookieName == "" {
		return fmt.Errorf("userSessionCookieName is required when forward auth is enabled")
	}
	if config.ResourceSessionRequestParam == "" {
		return fmt.Errorf("resourceSessionRequestParam is required when forward auth is enabled")
	}
	return nil
}

// parseTrustedIPs parses configured and default Cloudflare IP ranges into the Badger's trustIP list.
func (p *Badger) parseTrustedIPs(trustIPs []string, disableDefaultCFIPs bool) error {
	for _, v := range trustIPs {
		_, trustip, err := net.ParseCIDR(v)
		if err != nil {
			return err
		}
		p.trustIP = append(p.trustIP, trustip)
	}

	if !disableDefaultCFIPs {
		for _, v := range ips.CFIPs() {
			_, trustip, err := net.ParseCIDR(v)
			if err != nil {
				return err
			}
			p.trustIP = append(p.trustIP, trustip)
		}
	}
	return nil
}

func (p *Badger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	realIP := p.getRealIP(req)
	p.setIPHeaders(req, realIP)

	if p.disableForwardAuth {
		p.next.ServeHTTP(rw, req)
		return
	}

	cookies := p.extractCookies(req)
	queryValues := req.URL.Query()

	if sessionRequestValue := queryValues.Get(p.resourceSessionRequestParam); sessionRequestValue != "" {
		if p.handleSessionExchange(rw, req, sessionRequestValue, realIP) {
			return
		}
	}

	originalRequestURL := buildOriginalURL(req, queryValues)
	verifyURL := fmt.Sprintf("%s/badger/verify-session", p.apiBaseURL)

	cookieData := buildVerifyBody(req, cookies, originalRequestURL, realIP, queryValues)

	jsonData, err := json.Marshal(cookieData)
	if err != nil {
		http.Error(rw, errInternalServer, http.StatusInternalServerError)
		return
	}

	httpReq, err := http.NewRequestWithContext(req.Context(), http.MethodPost, verifyURL, bytes.NewBuffer(jsonData)) //nolint:gosec // G704: URL is constructed from configured apiBaseURL
	if err != nil {
		http.Error(rw, errInternalServer, http.StatusInternalServerError)
		return
	}
	httpReq.Header.Set(headerContentType, "application/json")

	resp, err := p.httpClient.Do(httpReq) //nolint:gosec // G704: URL is constructed from configured apiBaseURL
	if err != nil {
		http.Error(rw, errInternalServer, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for _, setCookie := range resp.Header[headerSetCookie] {
		rw.Header().Add(headerSetCookie, setCookie)
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(rw, errInternalServer, http.StatusInternalServerError)
		return
	}

	var result VerifyResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		http.Error(rw, errInternalServer, http.StatusInternalServerError)
		return
	}

	p.handleVerifyResponse(rw, req, result)
}

// handleSessionExchange processes a session exchange request.
// Returns true if the request was handled (response written), false if it should fall through to verification.
func (p *Badger) handleSessionExchange(rw http.ResponseWriter, req *http.Request, sessionRequestValue string, realIP string) bool {
	body := ExchangeSessionBody{
		RequestToken: &sessionRequestValue,
		RequestHost:  &req.Host,
		RequestIP:    &realIP,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		http.Error(rw, errInternalServer, http.StatusInternalServerError)
		return true
	}

	verifyURL := fmt.Sprintf("%s/badger/exchange-session", p.apiBaseURL)
	httpReq, err := http.NewRequestWithContext(req.Context(), http.MethodPost, verifyURL, bytes.NewBuffer(jsonData)) //nolint:gosec // G704: URL is constructed from configured apiBaseURL
	if err != nil {
		http.Error(rw, errInternalServer, http.StatusInternalServerError)
		return true
	}
	httpReq.Header.Set(headerContentType, "application/json")

	resp, err := p.httpClient.Do(httpReq) //nolint:gosec // G704: URL is constructed from configured apiBaseURL
	if err != nil {
		http.Error(rw, errInternalServer, http.StatusInternalServerError)
		return true
	}
	defer resp.Body.Close()

	var result ExchangeSessionResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		http.Error(rw, errInternalServer, http.StatusInternalServerError)
		return true
	}

	if result.Data.Cookie == nil || *result.Data.Cookie == "" {
		// No valid session cookie; fall through to verification
		return false
	}

	rw.Header().Add(headerSetCookie, *result.Data.Cookie)

	queryValues := req.URL.Query()
	queryValues.Del(p.resourceSessionRequestParam)
	cleanedQuery := queryValues.Encode()
	originalRequestURL := fmt.Sprintf("%s://%s%s", getScheme(req), req.Host, req.URL.Path)
	if cleanedQuery != "" {
		originalRequestURL = fmt.Sprintf("%s?%s", originalRequestURL, cleanedQuery)
	}

	if result.Data.ResponseHeaders != nil {
		for key, value := range result.Data.ResponseHeaders {
			rw.Header().Add(key, value)
		}
	}

	log.Printf("badger: got exchange token, redirecting to %s", originalRequestURL) //nolint:gosec // G706: originalRequestURL is derived from the incoming request
	http.Redirect(rw, req, originalRequestURL, http.StatusFound)                    //nolint:gosec // G710: redirect URL is constructed from the original request
	return true
}

// buildOriginalURL reconstructs the original request URL, stripping the session param.
func buildOriginalURL(req *http.Request, queryValues url.Values) string {
	cleanedQuery := queryValues.Encode()
	originalRequestURL := fmt.Sprintf("%s://%s%s", getScheme(req), req.Host, req.URL.Path)
	if cleanedQuery != "" {
		originalRequestURL = fmt.Sprintf("%s?%s", originalRequestURL, cleanedQuery)
	}
	return originalRequestURL
}

// buildVerifyBody constructs the verification request payload.
func buildVerifyBody(req *http.Request, cookies map[string]string, originalRequestURL string, realIP string, queryValues url.Values) VerifyBody {
	headers := make(map[string]string)
	for name, values := range req.Header {
		if len(values) > 0 {
			headers[name] = values[0] // Send only the first value for simplicity
		}
	}

	queryParams := make(map[string]string)
	for key, values := range queryValues {
		if len(values) > 0 {
			queryParams[key] = values[0]
		}
	}

	scheme := getScheme(req)
	return VerifyBody{
		Sessions:           cookies,
		OriginalRequestURL: originalRequestURL,
		RequestScheme:      &scheme,
		RequestHost:        &req.Host,
		RequestPath:        &req.URL.Path,
		RequestMethod:      &req.Method,
		TLS:                req.TLS != nil,
		RequestIP:          &realIP,
		Headers:            headers,
		Query:              queryParams,
		BadgerVersion:      version.Version,
	}
}

// handleVerifyResponse processes the verification response and writes the appropriate result.
func (p *Badger) handleVerifyResponse(rw http.ResponseWriter, req *http.Request, result VerifyResponse) {
	clearRemoteHeaders(req)
	applyResponseHeaders(rw, result.Data.ResponseHeaders)

	if result.Data.HeaderAuthChallenged {
		handleHeaderAuthChallenge(rw, result.Data.RedirectURL)
		return
	}

	if result.Data.RedirectURL != nil && *result.Data.RedirectURL != "" {
		log.Printf("badger: redirecting to %s", *result.Data.RedirectURL)  //nolint:gosec // G706: redirectURL comes from trusted auth server
		http.Redirect(rw, req, *result.Data.RedirectURL, http.StatusFound) //nolint:gosec // G710: redirect URL comes from the auth server
		return
	}

	if result.Data.Valid {
		setUserHeaders(req, &result.Data)
		if !result.Data.DontStripSession {
			p.stripSessionParam(req)
			p.stripSessionCookies(req)
			p.stripAccessTokenHeaders(req)
		}
		log.Printf("badger: valid session")
		p.next.ServeHTTP(rw, req)
		return
	}

	http.Error(rw, errUnauthorized, http.StatusUnauthorized)
}

// clearRemoteHeaders removes all remote-user headers from the request.
func clearRemoteHeaders(req *http.Request) {
	req.Header.Del(headerRemoteUser)
	req.Header.Del(headerRemoteEmail)
	req.Header.Del(headerRemoteName)
	req.Header.Del(headerRemoteRole)
	req.Header.Del(headerRemoteUserID)
}

// applyResponseHeaders copies response headers from the verification result to the response writer.
func applyResponseHeaders(rw http.ResponseWriter, headers map[string]string) {
	if headers == nil {
		return
	}
	for key, value := range headers {
		rw.Header().Add(key, value)
	}
}

// handleHeaderAuthChallenge responds with a 401 and optional redirect page for header-based auth.
func handleHeaderAuthChallenge(rw http.ResponseWriter, redirectURL *string) {
	log.Printf("badger: challenging client for header authentication")
	rw.Header().Add("WWW-Authenticate", "Basic realm=\"pangolin\"")

	if redirectURL != nil && *redirectURL != "" {
		rw.Header().Set(headerContentType, "text/html; charset=utf-8")
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte(renderRedirectPage(*redirectURL))) //nolint:gosec // G705: redirectURL comes from trusted auth server
	} else {
		http.Error(rw, errUnauthorized, http.StatusUnauthorized)
	}
}

// setUserHeaders sets the remote-user headers from the verification result.
func setUserHeaders(req *http.Request, data *VerifyResponseData) {
	if data.UserID != nil {
		req.Header.Add(headerRemoteUserID, *data.UserID)
	}
	if data.Username != nil {
		req.Header.Add(headerRemoteUser, *data.Username)
	}
	if data.Email != nil {
		req.Header.Add(headerRemoteEmail, *data.Email)
	}
	if data.Name != nil {
		req.Header.Add(headerRemoteName, *data.Name)
	}
	if data.Role != nil {
		req.Header.Add(headerRemoteRole, *data.Role)
	}
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

func getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

func renderRedirectPage(redirectURL string) string {
	htmlEscaped := html.EscapeString(redirectURL)
	jsEscaped := template.JSEscapeString(redirectURL)
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Redirecting...</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .container {
            text-align: center;
            padding: 2rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        a {
            color: #0066cc;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <p>Redirecting...</p>
        <p>If you are not redirected automatically, <a href="%s">click here</a>.</p>
    </div>
    <script>
        window.location.href = "%s";
    </script>
</body>
</html>`, htmlEscaped, jsEscaped)
}

func (p *Badger) getRealIP(req *http.Request) string {
	// Check if request comes from a trusted source
	isTrusted := p.isTrustedIP(req.RemoteAddr)

	// If custom IP header is configured, use it
	if p.customIPHeader != "" {
		if customIP := req.Header.Get(p.customIPHeader); customIP != "" && isTrusted {
			return customIP
		}
	}

	// Default: use CF-Connecting-IP if from trusted source
	if isTrusted {
		if cfIP := req.Header.Get(cfConnectingIP); cfIP != "" {
			return cfIP
		}
	}

	// Fallback: extract IP from RemoteAddr
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// If parsing fails, return RemoteAddr as-is (might be just IP without port)
		return req.RemoteAddr
	}
	return ip
}

func (p *Badger) stripSessionParam(req *http.Request) {
	query := req.URL.Query()
	modified := false
	if query.Has(p.resourceSessionRequestParam) {
		query.Del(p.resourceSessionRequestParam)
		modified = true
	}
	if p.accessTokenQueryParam != "" && query.Has(p.accessTokenQueryParam) {
		query.Del(p.accessTokenQueryParam)
		modified = true
	}
	if modified {
		req.URL.RawQuery = query.Encode()
	}
}

func (p *Badger) stripAccessTokenHeaders(req *http.Request) {
	if p.accessTokenIDHeader != "" {
		req.Header.Del(p.accessTokenIDHeader)
	}
	if p.accessTokenHeader != "" {
		req.Header.Del(p.accessTokenHeader)
	}
}

// stripSessionCookies removes session cookies from the request before forwarding to the backend.
// It processes raw Cookie header pairs so non-target cookies are preserved as-is.
func (p *Badger) stripSessionCookies(req *http.Request) {
	cookieHeaders := req.Header.Values("Cookie")
	if len(cookieHeaders) == 0 {
		return
	}

	var remainingPairs []string
	for _, headerValue := range cookieHeaders {
		for _, part := range strings.Split(headerValue, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, _, _ := strings.Cut(part, "=")
			name = strings.TrimSpace(name)
			if !strings.HasPrefix(name, p.userSessionCookieName) {
				remainingPairs = append(remainingPairs, part)
			}
		}
	}

	if len(remainingPairs) == 0 {
		req.Header.Del("Cookie")
		return
	}

	// Keep a single canonical Cookie header while preserving surviving name=value pairs.
	req.Header.Set("Cookie", strings.Join(remainingPairs, "; "))
}

func (p *Badger) isTrustedIP(remoteAddr string) bool {
	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, network := range p.trustIP {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *Badger) setIPHeaders(req *http.Request, realIP string) {
	isTrusted := p.isTrustedIP(req.RemoteAddr)

	if isTrusted {
		// Handle CF-Visitor header for scheme
		if req.Header.Get(cfVisitor) != "" {
			var cfVisitorValue struct {
				Scheme string `json:"scheme"`
			}
			if err := json.Unmarshal([]byte(req.Header.Get(cfVisitor)), &cfVisitorValue); err == nil {
				req.Header.Set(xForwardProto, cfVisitorValue.Scheme)
			}
		}

		// Set headers with the real IP (already extracted from CF-Connecting-IP or custom header)
		req.Header.Set(xForwardFor, realIP)
		req.Header.Set(xRealIP, realIP)
	} else {
		// Not from trusted source, use direct IP
		req.Header.Set(xRealIP, realIP)
		// Remove CF headers if present
		req.Header.Del(cfVisitor)
		req.Header.Del(cfConnectingIP)
	}
}
