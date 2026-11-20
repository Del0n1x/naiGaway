// Package auther validates proxy credentials.
package auther

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

type entry struct {
	encoded  string
	username string
}

// Auther holds pre-encoded credentials for constant-time comparison.
type Auther struct {
	entries []entry
}

// New validates and encodes credentials.
func New(credentials []Credential) (*Auther, error) {
	if len(credentials) == 0 {
		return nil, errors.New("at least one auth credential is required")
	}

	auther := &Auther{
		entries: make([]entry, 0, len(credentials)),
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
		auther.entries = append(auther.entries, entry{
			encoded:  base64.StdEncoding.EncodeToString(raw),
			username: credential.Username,
		})
	}
	return auther, nil
}

// Check validates the Proxy-Authorization header on req.
func (a *Auther) Check(req *http.Request) error {
	value := req.Header.Get("Proxy-Authorization")
	space := strings.IndexByte(value, ' ')
	if space < 0 {
		return errors.New("Proxy-Authorization is required")
	}
	if !strings.EqualFold(value[:space], "Basic") {
		return errors.New("unsupported proxy authentication type")
	}

	provided := value[space+1:]
	for _, credential := range a.entries {
		if !constantTimeStringEqual(credential.encoded, provided) {
			continue
		}
		if repl, ok := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
			repl.Set("http.auth.user.id", credential.username)
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
