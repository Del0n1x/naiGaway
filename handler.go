// Package naiveproxy implements a NaiveProxy server as a Caddy HTTP handler.
package naiveproxy

import (
	"fmt"
	"net"
	"time"

	"github.com/Del0n1x/naiGaway/internal/acl"
	"github.com/Del0n1x/naiGaway/internal/auth"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a Caddy HTTP handler that exposes a NaiveProxy endpoint.
//
// It is intentionally a forward proxy at its core: after authentication, a
// CONNECT request is tunneled to the requested target. NaiveProxy-specific
// behavior (padding, fast open and long-lived authenticated tunnels) is layered
// on top of that tunnel.
type Handler struct {
	// Auth is the list of accepted proxy credentials.
	Auth []auth.Credential `json:"auth,omitempty"`

	// Padding enables the NaiveProxy padding protocol. Default: true.
	Padding *bool `json:"padding,omitempty"`

	// FastOpen sends the CONNECT response before dialing the target. Default: true.
	FastOpen *bool `json:"fast_open,omitempty"`

	// IdleTimeout is the idle timeout applied to authenticated HTTP/2 and HTTP/3
	// tunnels. Default: 24h.
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`

	// DialTimeout limits the initial TCP connection to the target. Default: 30s.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// ACL controls destination ports, domains, and IP addresses.
	ACL acl.Config `json:"acl,omitempty"`

	authenticator *auth.Authenticator
	aclChecker    *acl.Checker
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.naive_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision prepares the handler.
func (h *Handler) Provision(_ caddy.Context) error {
	authenticator, err := auth.New(h.Auth)
	if err != nil {
		return err
	}
	h.authenticator = authenticator

	dialer := &net.Dialer{
		Timeout:   h.dialTimeout(),
		KeepAlive: 30 * time.Second,
	}

	checker, err := acl.New(h.ACL, dialer.DialContext)
	if err != nil {
		return err
	}
	h.aclChecker = checker

	return nil
}

// Validate checks the configuration.
func (h *Handler) Validate() error {
	if len(h.Auth) == 0 {
		return fmt.Errorf("at least one auth credential is required")
	}
	if h.DialTimeout < 0 {
		return fmt.Errorf("dial_timeout cannot be negative")
	}
	if h.IdleTimeout < 0 {
		return fmt.Errorf("idle_timeout cannot be negative")
	}
	return nil
}

func (h *Handler) paddingEnabled() bool {
	return boolDefault(h.Padding, true)
}

func (h *Handler) fastOpenEnabled() bool {
	return boolDefault(h.FastOpen, true)
}

func (h *Handler) dialTimeout() time.Duration {
	if h.DialTimeout == 0 {
		return 30 * time.Second
	}
	return time.Duration(h.DialTimeout)
}

func (h *Handler) idleTimeout() time.Duration {
	if h.IdleTimeout == 0 {
		return 24 * time.Hour
	}
	return time.Duration(h.IdleTimeout)
}

func boolDefault(value *bool, defaultValue bool) bool {
	if value == nil {
		return defaultValue
	}
	return *value
}

// Interface guards.
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
