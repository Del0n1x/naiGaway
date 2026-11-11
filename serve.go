package naiveproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/Del0n1x/naiGaway/internal/padding"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	authErr := h.authenticator.Check(r)

	if h.ProbeResistanceDomain != "" && strings.EqualFold(hostOnly(r.Host), h.ProbeResistanceDomain) {
		return serveProbePage(w, authErr)
	}

	// Non-CONNECT requests to the public hostname are ordinary website
	// requests. CONNECT requests always retain their target Host, so they are
	// never swallowed by this branch.
	if h.Hosts.Match(r) && r.Method != http.MethodConnect {
		return next.ServeHTTP(w, r)
	}

	// Probe resistance: never reveal the proxy with a 407. Unauthenticated
	// requests fall through to the normal website/reverse-proxy routes.
	if authErr != nil {
		return next.ServeHTTP(w, r)
	}

	if r.Method == http.MethodConnect {
		return h.serveConnect(w, r)
	}
	return h.serveHTTPProxy(w, r)
}

func hostOnly(host string) string {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
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

	return padding.DualStream(targetConn, clientConn, clientConn, false)
}

func (h *Handler) serveHTTPProxy(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	r.Proto = "HTTP/1.1"
	r.ProtoMajor = 1
	r.ProtoMinor = 1
	r.RequestURI = ""

	removeHopByHop(r.Header)

	if !h.HideIP {
		r.Header.Add("Forwarded", fmt.Sprintf("for=%q", r.RemoteAddr))
	}
	if !h.HideVia {
		r.Header.Add("Via", "1.1 caddy")
	}

	response, err := h.httpTransport.RoundTrip(r)
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("upstream request: %w", err))
	}
	defer response.Body.Close()

	if r.Body != nil {
		_ = r.Body.Close()
	}
	return forwardResponse(w, response, h.HideVia)
}

func forwardResponse(w http.ResponseWriter, response *http.Response, hideVia bool) error {
	w.Header().Del("Server")
	if !hideVia {
		w.Header().Add("Via", fmt.Sprintf("%d.%d caddy", response.ProtoMajor, response.ProtoMinor))
	}
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	removeHopByHop(w.Header())

	w.WriteHeader(response.StatusCode)

	buffer := responseBufferPool.Get().(*[]byte)
	defer responseBufferPool.Put(buffer)
	if _, err := io.CopyBuffer(w, response.Body, *buffer); err != nil {
		return fmt.Errorf("copy response body: %w", err)
	}
	return nil
}

var responseBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, 64*1024)
		return &buffer
	},
}

func removeHopByHop(header http.Header) {
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			header.Del(name)
		}
	}
	for _, name := range hopByHopHeaders {
		header.Del(name)
	}
}

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}
