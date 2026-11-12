package naiveproxy

import (
	"fmt"
	"net"
	"net/http"

	"github.com/Del0n1x/naiGaway/internal/padding"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// This handler only proxies CONNECT. Ordinary HTTP requests always fall
	// through to the website/reverse-proxy routes, whether authenticated or not.
	if r.Method != http.MethodConnect {
		return next.ServeHTTP(w, r)
	}
	if h.authenticator.Check(r) != nil {
		return next.ServeHTTP(w, r)
	}
	return h.serveConnect(w, r)
}

func (h *Handler) serveConnect(w http.ResponseWriter, r *http.Request) error {
	if r.ProtoMajor == 2 || r.ProtoMajor == 3 {
		if r.URL.Scheme != "" || r.URL.Path != "" {
			return caddyhttp.Error(http.StatusBadRequest,
				fmt.Errorf("CONNECT request contains :scheme or :path"))
		}
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
			return h.failConnect(w, r, err)
		}
		return err
	}
	defer targetConn.Close()

	switch r.ProtoMajor {
	case 1:
		return serveHijack(w, targetConn, fastOpen)
	case 2, 3:
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
	default:
		return caddyhttp.Error(http.StatusHTTPVersionNotSupported,
			fmt.Errorf("unsupported HTTP version %d", r.ProtoMajor))
	}
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

func (h *Handler) failConnect(w http.ResponseWriter, r *http.Request, cause error) error {
	if r.ProtoMajor == 1 {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			_ = conn.Close()
			return nil
		}
	}
	return caddyhttp.Error(http.StatusBadGateway, cause)
}

func serveHijack(w http.ResponseWriter, targetConn net.Conn, alreadyResponded bool) error {
	if !alreadyResponded {
		w.WriteHeader(http.StatusOK)
	}

	clientConn, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("hijack CONNECT: %w", err))
	}
	defer clientConn.Close()

	if n := buffered.Reader.Buffered(); n > 0 {
		data, _ := buffered.Reader.Peek(n)
		if _, err := targetConn.Write(data); err != nil {
			return fmt.Errorf("forward buffered client data: %w", err)
		}
	}
	if err := buffered.Flush(); err != nil {
		return fmt.Errorf("flush hijacked connection: %w", err)
	}

	return padding.RawDualStream(targetConn, clientConn)
}
