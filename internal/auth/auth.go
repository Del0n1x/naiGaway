// Package auth validates proxy credentials.
package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
)

// Credential is a proxy username/password pair.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Authenticator holds pre-encoded credentials for constant-time comparison.
type Authenticator struct {
	credentials [][]byte
}

// New validates and encodes credentials.
func New(credentials []Credential) (*Authenticator, error) {
	if len(credentials) == 0 {
		return nil, errors.New("at least one auth credential is required")
	}

	authenticator := &Authenticator{credentials: make([][]byte, 0, len(credentials))}
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
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
		base64.StdEncoding.Encode(encoded, raw)
		authenticator.credentials = append(authenticator.credentials, encoded)
	}
	return authenticator, nil
}

// Check validates the Proxy-Authorization header on req.
func (a *Authenticator) Check(req *http.Request) error {
	parts := strings.SplitN(req.Header.Get("Proxy-Authorization"), " ", 2)
	if len(parts) != 2 {
		return errors.New("Proxy-Authorization is required")
	}
	if !strings.EqualFold(parts[0], "Basic") {
		return errors.New("unsupported proxy authentication type")
	}

	provided := []byte(parts[1])
	for _, expected := range a.credentials {
		if subtle.ConstantTimeCompare(expected, provided) != 1 {
			continue
		}
		if repl, ok := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
			if user := decodeUser(expected); user != "" {
				repl.Set("http.auth.user.id", user)
			}
		}
		return nil
	}

	if repl, ok := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set("http.auth.user.id", "invalid")
	}
	return errors.New("invalid credentials")
}

func decodeUser(encoded []byte) string {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil || !utf8.Valid(decoded[:n]) {
		return ""
	}
	credential := string(decoded[:n])
	if index := strings.IndexByte(credential, ':'); index >= 0 {
		return credential[:index]
	}
	return ""
}
