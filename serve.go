package naiveproxy

import (
	"fmt"
	"net/http"

	"github.com/Del0n1x/naiGaway/internal/padding"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// This handler only proxies HTTP/2 and HTTP/3 CONNECT. Everything else
	// falls through to the website/reverse-proxy routes.
	if r.Method != http.MethodConnect || (r.ProtoMajor != 2 && r.ProtoMajor != 3) {
		return next.ServeHTTP(w, r)
	}
	if h.authenticator.Check(r) != nil {
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
	fastOpen := h.fastOpenEnabled()

	if fastOpen {
		if err := h.writeConnectResponse(w, usePadding, paddingReply); err != nil {
			return err
		}
	}

	targetConn, err := h.aclChecker.DialContext(r.Context(), "tcp", hostPort)
	if err != nil {
		if fastOpen {
			return caddyhttp.Error(http.StatusBadGateway, err)
		}
		return err
	}
	defer targetConn.Close()

	if !fastOpen {
		if err := h.writeConnectResponse(w, usePadding, paddingReply); err != nil {
			return err
		}
	}
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
