package naiveproxy

import (
	"fmt"
	"net/http"
)

// serveProbePage is used only for the optional secret hostname. It gives
// browsers a chance to receive a 407 and cache proxy credentials, while all
// other unauthenticated requests fall through to the normal website.
func serveProbePage(w http.ResponseWriter, authErr error) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if authErr == nil {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!doctype html><title>OK</title><p>OK</p>"))
		return nil
	}

	w.Header().Set("Proxy-Authenticate", `Basic realm="restricted"`)
	w.WriteHeader(http.StatusProxyAuthRequired)
	_, _ = fmt.Fprint(w, `<!doctype html><title>Authentication Required</title><p>Authentication required.</p>`)
	// The 407 is intentional; do not surface it as a handler error in logs.
	return nil
}
