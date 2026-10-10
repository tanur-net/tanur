// SPDX-License-Identifier: MPL-2.0

package skin

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"

	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
)

// ServerConfig configures the outer skin server.
type ServerConfig struct {
	// TLS is the real TLS config: a genuine certificate for the real domain.
	TLS *tls.Config
	// Static is the inner channel's server static key.
	Static inner.StaticKey
	// Recipe shapes inner frames for this deployment.
	Recipe recipe.Recipe
	// DoorSecret is the shared secret that distinguishes a Tanur client from a
	// browser. Empty disables the door (every TLS client is treated as Tanur);
	// only sensible in tests.
	DoorSecret string
	// Site serves ordinary browsers and anything that fails the door check. If
	// nil, non-Tanur requests get a minimal 200 page.
	Site http.Handler
	// OnInner is called with an established inner Conn for each Tanur client.
	OnInner func(*inner.Conn)
}

// Header names the client uses to present the door. They look like ordinary
// request headers; their values carry the nonce and token.
const (
	hdrNonce = "X-Request-Id"      // carries the client nonce (hex)
	hdrToken = "X-Request-Session" // carries the HMAC token (hex)
)

// Serve accepts one already-TLS-terminated connection. It reads the first HTTP
// request: a valid door hands the connection to the inner channel; anything
// else is served the real site. The caller does the TLS Accept and passes the
// *tls.Conn so this stays testable.
func (s *ServerConfig) Serve(tc net.Conn) error {
	br := bufio.NewReader(tc)
	req, err := http.ReadRequest(br)
	if err != nil {
		tc.Close()
		return err
	}

	if s.DoorSecret == "" || s.doorOK(req) {
		// Upgrade to the inner channel over the same TLS stream. Any buffered
		// bytes already read by br must be preserved ahead of the live conn.
		stream := prefixConn(tc, br.Buffered(), br)
		conn, err := inner.Server(stream, s.Static, s.Recipe)
		if err != nil {
			tc.Close()
			return err
		}
		if s.OnInner != nil {
			s.OnInner(conn)
		}
		return nil
	}

	// Not a Tanur client: serve the real site and keep the socket looking like
	// an ordinary web server.
	s.serveSite(tc, req)
	return nil
}

func (s *ServerConfig) doorOK(req *http.Request) bool {
	nonce := req.Header.Get(hdrNonce)
	token := req.Header.Get(hdrToken)
	if nonce == "" || token == "" {
		return false
	}
	return verifyDoor(s.DoorSecret, nonce, token)
}

func (s *ServerConfig) serveSite(tc net.Conn, req *http.Request) {
	defer tc.Close()
	rw := &respWriter{conn: tc, header: http.Header{}}
	if s.Site != nil {
		s.Site.ServeHTTP(rw, req)
	} else {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.WriteHeader(200)
		_, _ = io.WriteString(rw, "<!doctype html><title>OK</title><p>It works.</p>\n")
	}
	rw.flush()
}
