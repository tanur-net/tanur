// SPDX-License-Identifier: MPL-2.0

package skin

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
)

// ClientConfig configures the outer skin client.
type ClientConfig struct {
	// Addr is host:port to dial (the real domain's address).
	Addr string
	// TLS is the TLS client config; ServerName must be the real domain. In
	// production the handshake uses a browser fingerprint (uTLS); this standard
	// config is the baseline and the loopback-test path.
	TLS *tls.Config
	// ServerPub is the inner channel server's public key (from the recipe).
	ServerPub []byte
	// Recipe shapes inner frames.
	Recipe recipe.Recipe
	// DoorSecret is the shared door secret (from the recipe).
	DoorSecret string
	// Host is the HTTP Host header to send; defaults to TLS.ServerName.
	Host string
	// Path is the request path; defaults to "/".
	Path string
	// ECHConfigList, when set, makes the client encrypt its ClientHello (ECH) so
	// the real SNI never appears in clear. It is a raw ECHConfigList (already
	// base64-decoded from the recipe). Empty = ordinary TLS with visible SNI.
	ECHConfigList []byte
}

// effectiveTLS returns the TLS config to dial with: the caller's config, cloned
// and augmented with ECH when an ECHConfigList is present. Cloning keeps the
// caller's config untouched across dials.
func (c *ClientConfig) effectiveTLS() *tls.Config {
	if len(c.ECHConfigList) == 0 {
		return c.TLS
	}
	cfg := c.TLS.Clone()
	cfg.EncryptedClientHelloConfigList = c.ECHConfigList
	return cfg
}

// Dial opens the outer TLS connection, presents the door, and returns an
// established inner Conn ready for application data.
func (c *ClientConfig) Dial() (*inner.Conn, error) {
	raw, err := net.Dial("tcp", c.Addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, c.effectiveTLS())
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}

	if err := c.sendDoor(tc); err != nil {
		tc.Close()
		return nil, err
	}

	conn, err := inner.Client(tc, c.ServerPub, c.Recipe)
	if err != nil {
		tc.Close()
		return nil, err
	}
	return conn, nil
}

// sendDoor writes an ordinary-looking HTTP/1.1 request whose headers carry the
// door nonce and token. After this request the server upgrades the same stream
// to the inner channel, so no response is read here.
func (c *ClientConfig) sendDoor(w io.Writer) error {
	var nb [16]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nb[:])
	token := doorToken(c.DoorSecret, nonce)

	host := c.Host
	if host == "" {
		host = c.TLS.ServerName
	}
	path := c.Path
	if path == "" {
		path = "/"
	}

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\n%s: %s\r\nConnection: keep-alive\r\n\r\n",
		path, host, hdrNonce, nonce, hdrToken, token,
	)
	_, err := io.WriteString(w, req)
	return err
}
