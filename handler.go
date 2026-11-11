// Package naiveproxy implements a NaiveProxy server as a Caddy HTTP handler.
package naiveproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Del0n1x/naiGaway/internal/acl"
	"github.com/Del0n1x/naiGaway/internal/auth"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
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
	// Hosts are the public hostnames of this NaiveProxy endpoint. They are used
	// only to route ordinary website requests to the next handler; CONNECT
	// requests are routed by their target host and are unaffected.
	Hosts caddyhttp.MatchHost `json:"hosts,omitempty"`

	// Auth is the list of accepted proxy credentials.
	Auth []auth.Credential `json:"auth,omitempty"`

	// ProbeResistanceDomain is an optional secret hostname. Requests for this
	// host receive an authentication page instead of falling through to the
	// website. Naive clients do not need it because they send credentials
	// preemptively.
	ProbeResistanceDomain string `json:"probe_resistance_domain,omitempty"`

	// HideIP prevents the client IP from being added to Forwarded headers on
	// plain HTTP proxy requests.
	HideIP bool `json:"hide_ip,omitempty"`

	// HideVia prevents the Via header from being added on plain HTTP proxy
	// requests.
	HideVia bool `json:"hide_via,omitempty"`

	// Padding enables the NaiveProxy padding protocol. Default: true.
	Padding *bool `json:"padding,omitempty"`

	// FastOpen sends the CONNECT response before dialing the target. Default: true.
	FastOpen *bool `json:"fast_open,omitempty"`

	// IdleTimeout is the idle timeout applied to authenticated HTTP/2 and HTTP/3
	// tunnels. Default: 24h.
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`

	// DialTimeout limits the initial TCP connection to the target. Default: 30s.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// MaxIdleConns is the maximum number of idle connections kept by the plain
	// HTTP proxy transport. Default: 50.
	MaxIdleConns int `json:"max_idle_conns,omitempty"`

	// MaxIdleConnsPerHost is the maximum number of idle connections per target.
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`

	// AllowedPorts restricts CONNECT and HTTP proxy targets to these ports.
	// Empty means all ports.
	AllowedPorts []int `json:"allowed_ports,omitempty"`

	// ACL is evaluated before the built-in private-range denials.
	ACL []acl.Rule `json:"acl,omitempty"`

	logger        *zap.Logger
	authenticator *auth.Authenticator
	aclChecker    *acl.Checker
	httpTransport *http.Transport
	dialContext   func(context.Context, string, string) (net.Conn, error)
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.naive_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision prepares the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	authenticator, err := auth.New(h.Auth)
	if err != nil {
		return err
	}
	h.authenticator = authenticator

	if h.DialTimeout <= 0 {
		h.DialTimeout = caddy.Duration(30 * time.Second)
	}
	if h.IdleTimeout <= 0 {
		h.IdleTimeout = caddy.Duration(24 * time.Hour)
	}

	maxIdleConns := h.MaxIdleConns
	if maxIdleConns == 0 {
		maxIdleConns = 50
	}
	if maxIdleConns < 0 {
		maxIdleConns = 0
	}

	h.httpTransport = &http.Transport{
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: h.MaxIdleConnsPerHost,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	dialer := &net.Dialer{
		Timeout:   time.Duration(h.DialTimeout),
		KeepAlive: 30 * time.Second,
	}
	h.dialContext = dialer.DialContext

	checker, err := acl.New(h.ACL, h.AllowedPorts, h.dialContext)
	if err != nil {
		return err
	}
	h.aclChecker = checker
	h.httpTransport.DialContext = checker.DialContext

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
	if h.ProbeResistanceDomain != "" {
		domain := strings.TrimSuffix(strings.ToLower(h.ProbeResistanceDomain), ".")
		if err := acl.ValidDomain(domain); err != nil {
			return fmt.Errorf("invalid probe_resistance_domain: %w", err)
		}
	}
	for _, port := range h.AllowedPorts {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("allowed port %d is outside 1-65535", port)
		}
	}
	return nil
}

// Cleanup releases idle connections.
func (h *Handler) Cleanup() error {
	if h.httpTransport != nil {
		h.httpTransport.CloseIdleConnections()
	}
	return nil
}

func (h *Handler) paddingEnabled() bool {
	return boolDefault(h.Padding, true)
}

func (h *Handler) fastOpenEnabled() bool {
	return boolDefault(h.FastOpen, true)
}

func (h *Handler) idleTimeout() time.Duration {
	if h.IdleTimeout <= 0 {
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
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
