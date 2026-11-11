// Package auth validates proxy credentials.
package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

// Credential is a proxy username/password pair.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Authenticator holds pre-encoded credentials for constant-time comparison.
type Authenticator struct {
	credentials []string
	usernames   []string
}

// New validates and encodes credentials.
func New(credentials []Credential) (*Authenticator, error) {
	if len(credentials) == 0 {
		return nil, errors.New("at least one auth credential is required")
	}

	authenticator := &Authenticator{
		credentials: make([]string, 0, len(credentials)),
		usernames:   make([]string, 0, len(credentials)),
	}
	for _, credential := range credentials {
		if credential.Username == "" {
			return nil, errors.New("auth username cannot be empty")
		}
		if strings.ContainsRune(credential.Username, ':') {
			return nil, errors.New("auth username cannot contain ':'")
		}
		if credential.Password == "" {
			return nil, errors.New("auth password cannot be empty")
		}

		raw := []byte(credential.Username + ":" + credential.Password)
		encoded := base64.StdEncoding.EncodeToString(raw)
		authenticator.credentials = append(authenticator.credentials, encoded)
		authenticator.usernames = append(authenticator.usernames, credential.Username)
	}
	return authenticator, nil
}

// Check validates the Proxy-Authorization header on req.
func (a *Authenticator) Check(req *http.Request) error {
	value := req.Header.Get("Proxy-Authorization")
	space := strings.IndexByte(value, ' ')
	if space < 0 {
		return errors.New("Proxy-Authorization is required")
	}
	if !strings.EqualFold(value[:space], "Basic") {
		return errors.New("unsupported proxy authentication type")
	}

	provided := value[space+1:]
	for i, expected := range a.credentials {
		if !constantTimeStringEqual(expected, provided) {
			continue
		}
		if repl, ok := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
			repl.Set("http.auth.user.id", a.usernames[i])
		}
		return nil
	}

	if repl, ok := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set("http.auth.user.id", "invalid")
	}
	return errors.New("invalid credentials")
}

// constantTimeStringEqual compares equal-length strings without early exit on
// content. Length is compared first, matching crypto/subtle behavior.
func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := 0; i < len(a); i++ {
		different |= a[i] ^ b[i]
	}
	return different == 0
}
