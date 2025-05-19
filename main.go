package badger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Config struct {
	APIBaseUrl                  string   `json:"apiBaseUrl"`
	UserSessionCookieName       string   `json:"userSessionCookieName"`
	ResourceSessionRequestParam string   `json:"resourceSessionRequestParam"`
	TrustedIPs                  []string `json:"trustedIps"`
}

type Badger struct {
	next                        http.Handler
	name                        string
	apiBaseUrl                  string
	userSessionCookieName       string
	resourceSessionRequestParam string
	trustedIPNets               []*net.IPNet
	trustedIPs                  map[string]bool
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
	badger := &Badger{
		next:                        next,
		name:                        name,
		apiBaseUrl:                  config.APIBaseUrl,
		userSessionCookieName:       config.UserSessionCookieName,
		resourceSessionRequestParam: config.ResourceSessionRequestParam,
		trustedIPs:                  make(map[string]bool),
		trustedIPNets:               []*net.IPNet{},
	}

	// Parse the trusted IPs
	for _, ipStr := range config.TrustedIPs {
		// Check if it's a CIDR notation
		if strings.Contains(ipStr, "/") {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err == nil {
				badger.trustedIPNets = append(badger.trustedIPNets, ipNet)
			} else {
				fmt.Printf("Warning: Invalid CIDR notation in TrustedIPs: %s\n", ipStr)
			}
		} else {
			// It's a single IP address
			ip := net.ParseIP(ipStr)
			if ip != nil {
				badger.trustedIPs[ipStr] = true
			} else {
				fmt.Printf("Warning: Invalid IP address in TrustedIPs: %s\n", ipStr)
			}
		}
	}

	return badger, nil
}

func (p *Badger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cookies := p.extractCookies(req)

	queryValues := req.URL.Query()

	if sessionRequestValue := queryValues.Get(p.resourceSessionRequestParam); sessionRequestValue != "" {
		realIP := p.getRealIP(req)
		body := ExchangeSessionBody{
			RequestToken: &sessionRequestValue,
			RequestHost:  &req.Host,
			RequestIP:    &realIP,
		}

		jsonData, err := json.Marshal(body)
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		verifyURL := fmt.Sprintf("%s/badger/exchange-session", p.apiBaseUrl)
		resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var result ExchangeSessionResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if result.Data.Cookie != nil && *result.Data.Cookie != "" {
			rw.Header().Add("Set-Cookie", *result.Data.Cookie)

			queryValues.Del(p.resourceSessionRequestParam)
			cleanedQuery := queryValues.Encode()
			originalRequestURL := fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.Path)
			if cleanedQuery != "" {
				originalRequestURL = fmt.Sprintf("%s?%s", originalRequestURL, cleanedQuery)
			}

			if result.Data.ResponseHeaders != nil {
				for key, value := range result.Data.ResponseHeaders {
					rw.Header().Add(key, value)
				}
			}

			fmt.Println("Got exchange token, redirecting to", originalRequestURL)
			http.Redirect(rw, req, originalRequestURL, http.StatusFound)
			return
		}
	}

	cleanedQuery := queryValues.Encode()
	originalRequestURL := fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.Path)
	if cleanedQuery != "" {
		originalRequestURL = fmt.Sprintf("%s?%s", originalRequestURL, cleanedQuery)
	}

	verifyURL := fmt.Sprintf("%s/badger/verify-session", p.apiBaseUrl)

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

	realIP := p.getRealIP(req)
	cookieData := VerifyBody{
		Sessions:           cookies,
		OriginalRequestURL: originalRequestURL,
		RequestScheme:      &req.URL.Scheme,
		RequestHost:        &req.Host,
		RequestPath:        &req.URL.Path,
		RequestMethod:      &req.Method,
		TLS:                req.TLS != nil,
		RequestIP:          &realIP,
		Headers:            headers,
		Query:              queryParams,
	}

	jsonData, err := json.Marshal(cookieData)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError) // TODO: redirect to error page
		return
	}

	resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for _, setCookie := range resp.Header["Set-Cookie"] {
		rw.Header().Add("Set-Cookie", setCookie)
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var result VerifyResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if result.Data.ResponseHeaders != nil {
		for key, value := range result.Data.ResponseHeaders {
			rw.Header().Add(key, value)
		}
	}

	if result.Data.RedirectURL != nil && *result.Data.RedirectURL != "" {
		fmt.Println("Badger: Redirecting to", *result.Data.RedirectURL)
		http.Redirect(rw, req, *result.Data.RedirectURL, http.StatusFound)
		return
	}

	if result.Data.Valid {
		fmt.Println("Badger: Valid session")
		p.next.ServeHTTP(rw, req)
		return
	}

	http.Error(rw, "Unauthorized", http.StatusUnauthorized)
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

// isTrustedIP checks if the given IP is in the trusted list
func (p *Badger) isTrustedIP(ipStr string) bool {
	// Extract IP from "IP:port" format if needed
	host, _, err := net.SplitHostPort(ipStr)
	if err != nil {
		// If error, use the original string (might not have a port)
		host = ipStr
	}

	// First check direct IP match
	if p.trustedIPs[host] {
		return true
	}

	// Then check CIDR blocks
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, ipNet := range p.trustedIPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// getRealIP returns the real client IP, considering headers if the request is from a trusted source
func (p *Badger) getRealIP(req *http.Request) string {
	remoteIP := req.RemoteAddr

	if p.isTrustedIP(remoteIP) {
		// Try CloudFlare's header first
		if cfIP := req.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return cfIP
		}

		// Then try X-Real-IP
		if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
			return realIP
		}

		// Then try X-Forwarded-For
		if forwardedFor := req.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			// X-Forwarded-For can contain multiple IPs, take the first one
			ips := strings.Split(forwardedFor, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
	}

	// Fall back to remote address
	host, _, err := net.SplitHostPort(remoteIP)
	if err != nil {
		return remoteIP // Return as is if there's no port
	}
	return host
}
