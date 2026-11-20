// Package naiveproxy implements a NaiveProxy server as a Caddy HTTP handler.
package naiveproxy

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Del0n1x/caddyNaive/internal/auther"
	"github.com/Del0n1x/caddyNaive/internal/dialer"
	"github.com/Del0n1x/caddyNaive/internal/dialer/acl"
	"github.com/Del0n1x/caddyNaive/internal/padding"
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
// behavior (padding and long-lived authenticated tunnels) is layered on top of
// that tunnel.
type Handler struct {
	// Auth is the list of accepted proxy credentials.
	Auth []auther.Credential `json:"auth,omitempty"`

	// Padding enables the NaiveProxy padding protocol. Default: true.
	Padding *bool `json:"padding,omitempty"`

	// IdleTimeout is the idle timeout applied to authenticated HTTP/2 and HTTP/3
	// tunnels. Default: 24h.
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`

	// DialTimeout limits target resolution and connection establishment.
	// Default: 30s.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// ACL controls destination ports, domains, and IP addresses.
	ACL acl.Config `json:"acl,omitempty"`

	// Runtime state built once by Provision. All values are immutable and
	// safe for concurrent use after provisioning.
	auther *auther.Auther
	dialer *dialer.Dialer
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
	a, err := auther.New(h.Auth)
	if err != nil {
		return err
	}
	h.auther = a

	targetDialer, err := dialer.New(dialer.Config{
		ACL:       h.ACL,
		Timeout:   h.dialTimeout(),
		KeepAlive: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	h.dialer = targetDialer

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

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// This handler only proxies HTTP/2 and HTTP/3 CONNECT. Everything else
	// falls through to the website/reverse-proxy routes.
	if r.Method != http.MethodConnect || (r.ProtoMajor != 2 && r.ProtoMajor != 3) {
		return next.ServeHTTP(w, r)
	}
	if h.auther.Check(r) != nil {
		return next.ServeHTTP(w, r)
	}

	return h.serveConnect(w, r)
}

func (h *Handler) serveConnect(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Scheme != "" || r.URL.Path != "" {
		return caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("CONNECT request contains :scheme or :path"))
	}

	hostPort := r.URL.Host
	if hostPort == "" {
		hostPort = r.Host
	}

	usePadding, paddingReply := padding.Negotiate(r.Header, h.paddingEnabled())
	if err := h.writeConnectResponse(w, usePadding, paddingReply); err != nil {
		return err
	}

	targetConn, err := h.dialer.Dial(r.Context(), hostPort)
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, err)
	}
	defer targetConn.Close()

	if reader, _ := caddyhttp.IdleTimeoutsFromContext(r.Context()); reader != nil {
		reader.Override(h.idleTimeout(), 0)
	}
	defer r.Body.Close()
	return padding.DualStream(targetConn, r.Body, w, usePadding)
}

func (h *Handler) writeConnectResponse(w http.ResponseWriter, usePadding bool, paddingReply string) error {
	w.Header().Set(padding.TypeReplyHeader, paddingReply)
	if usePadding {
		w.Header().Set(padding.Header, padding.NewHeader())
	}
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("flush CONNECT response: %w", err))
	}
	return nil
}

func (h *Handler) paddingEnabled() bool {
	return boolDefault(h.Padding, true)
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
