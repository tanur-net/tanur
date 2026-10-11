// SPDX-License-Identifier: MPL-2.0

package skin

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"

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
	// ClientHelloID selects the browser fingerprint the outer handshake mimics
	// (uTLS), e.g. "chrome", "firefox", "safari", "edge", "ios", "randomized".
	// A real browser accent is what lets the handshake pass DPI that drops the
	// distinctive Go/crypto-tls ClientHello (field intel: Irancell blocks the
	// "unsafe" fingerprint). Empty = plain crypto/tls — only for loopback tests;
	// production must set this (the engine defaults it to "chrome").
	ClientHelloID string
}

// utlsHelloID maps a recipe's ClientHelloID name to a uTLS preset. The "_Auto"
// presets track a current browser version, so the accent stays fresh as uTLS
// updates. "golang" is the bare crypto/tls profile (distinctive — avoid in prod).
func utlsHelloID(name string) (utls.ClientHelloID, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome", "chrome_auto":
		return utls.HelloChrome_Auto, true
	case "firefox", "firefox_auto":
		return utls.HelloFirefox_Auto, true
	case "safari", "safari_auto":
		return utls.HelloSafari_Auto, true
	case "edge", "edge_auto":
		return utls.HelloEdge_Auto, true
	case "ios", "ios_auto":
		return utls.HelloIOS_Auto, true
	case "randomized", "random":
		return utls.HelloRandomized, true
	case "golang", "go":
		return utls.HelloGolang, true
	}
	return utls.ClientHelloID{}, false
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

// handshake performs the outer TLS handshake over raw and returns the connected
// stream. When ClientHelloID is set it uses uTLS to send a real browser's
// ClientHello (the accent that passes fingerprint DPI); otherwise it falls back
// to plain crypto/tls for loopback tests. Both return values implement
// net.Conn, so the door write and the inner channel ride either the same way.
func (c *ClientConfig) handshake(raw net.Conn) (net.Conn, error) {
	if c.ClientHelloID == "" {
		tc := tls.Client(raw, c.effectiveTLS())
		if err := tc.Handshake(); err != nil {
			return nil, err
		}
		return tc, nil
	}

	id, ok := utlsHelloID(c.ClientHelloID)
	if !ok {
		return nil, fmt.Errorf("unknown client_hello_id %q", c.ClientHelloID)
	}
	// Build a uTLS config from the caller's crypto/tls config. We copy only the
	// fields that matter for the outer handshake; the browser preset supplies the
	// ciphers, curves, extensions and their order (the fingerprint itself).
	ucfg := &utls.Config{
		ServerName:         c.TLS.ServerName,
		NextProtos:         c.TLS.NextProtos,
		InsecureSkipVerify: c.TLS.InsecureSkipVerify,
		RootCAs:            c.TLS.RootCAs,
	}
	if len(c.ECHConfigList) > 0 {
		// ECH requires TLS 1.3; the preset already offers it.
		ucfg.EncryptedClientHelloConfigList = c.ECHConfigList
		ucfg.MinVersion = tls.VersionTLS13
	}
	uconn := utls.UClient(raw, ucfg, id)
	if err := uconn.Handshake(); err != nil {
		return nil, err
	}
	return uconn, nil
}

// Dial opens the outer TLS connection, presents the door, and returns an
// established inner Conn ready for application data.
func (c *ClientConfig) Dial() (*inner.Conn, error) {
	raw, err := net.Dial("tcp", c.Addr)
	if err != nil {
		return nil, &stageErr{stage: "tcp", err: err}
	}
	tc, err := c.handshake(raw)
	if err != nil {
		raw.Close()
		return nil, &stageErr{stage: "tls", err: err}
	}

	if err := c.sendDoor(tc); err != nil {
		tc.Close()
		return nil, &stageErr{stage: "door", err: err}
	}

	conn, err := inner.Client(tc, c.ServerPub, c.Recipe)
	if err != nil {
		tc.Close()
		return nil, &stageErr{stage: "inner", err: err}
	}
	return conn, nil
}

// DialStage reports which phase of Dial produced err — "tcp", "tls", "door" or
// "inner" — or "" if err did not come from Dial. It lets the engine tag
// anonymous telemetry with WHERE a block happened (e.g. a TLS reset vs an
// inner-channel drop), carrying no user identity.
func DialStage(err error) string {
	var se *stageErr
	if errors.As(err, &se) {
		return se.stage
	}
	return ""
}

type stageErr struct {
	stage string
	err   error
}

func (e *stageErr) Error() string { return e.stage + ": " + e.err.Error() }
func (e *stageErr) Unwrap() error { return e.err }

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
