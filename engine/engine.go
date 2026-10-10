// SPDX-License-Identifier: MPL-2.0

// Package engine is the single door an app uses. It wires every piece together:
// it fetches the signed per-user endpoint list (brain), builds a ladder across
// carriers (CDN / direct), dials the best working path, runs the secure
// multiplexed channel, exposes a local SOCKS5 proxy, reconnects transparently on
// failure, and reports anonymous telemetry so the server can retire dead hosts.
//
// An app calls New then Start; it points its traffic at the local SOCKS address.
// Everything below (handshake, mux, shaping, carrier choice, failover) is hidden.
package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/tanur-net/tanur/brain"
	"github.com/tanur-net/tanur/carrier"
	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
	"github.com/tanur-net/tanur/skin"
	"github.com/tanur-net/tanur/tunnel"
)

// Config is everything the engine needs from the app.
type Config struct {
	// User identifies this user for the per-user endpoint subset (not logged
	// with outcomes; telemetry stays anonymous).
	User string
	// AssignURL is where to fetch the signed endpoint list (behind fronts). If
	// empty, Endpoints is used directly.
	AssignURL string
	// BrainPub verifies the signed assignment.
	BrainPub ed25519.PublicKey
	// Endpoints, when AssignURL is empty, is the endpoint list to use directly.
	Endpoints []brain.PoolEndpoint
	// Recipe shapes the inner channel (one recipe for all endpoints in v1).
	Recipe recipe.Recipe
	// SocksAddr is the local SOCKS5 listen address.
	SocksAddr string
	// ReportURL is the anonymous telemetry ingest endpoint (optional).
	ReportURL string
	// Network returns the current operator key (e.g. MCC/MNC) for per-operator
	// laddering and telemetry. Required.
	Network func() string
	// Cooldown is the ladder penalty-box duration.
	Cooldown time.Duration
	// HTTPClient is used for carrier/assignment/report calls; nil = a sensible
	// default with no overall timeout (carrier streams are long-lived).
	HTTPClient *http.Client
	// SkinTLS is a template TLS config for "skin" endpoints. The engine clones it
	// per dial and sets ServerName (and ECH) itself, so a caller uses this only to
	// supply roots or, in tests, InsecureSkipVerify. nil = verify with the system
	// roots at TLS 1.3.
	SkinTLS *tls.Config
}

// Engine is a running tunnel.
type Engine struct {
	cfg      Config
	ladder   *brain.Ladder
	client   *http.Client
	reporter string // rotating, non-identifying token for telemetry dedup

	mu  sync.Mutex
	mux *inner.Mux
	ln  net.Listener
}

// New builds an engine from config. It does not touch the network yet.
func New(cfg Config) (*Engine, error) {
	if cfg.Network == nil {
		return nil, errors.New("engine: Config.Network is required")
	}
	if cfg.SocksAddr == "" {
		cfg.SocksAddr = "127.0.0.1:1080"
	}
	if cfg.Cooldown == 0 {
		cfg.Cooldown = 3 * time.Minute
	}
	client := cfg.HTTPClient
	if client == nil {
		// The carrier opens two long-lived requests (a streaming down GET and a
		// streaming up POST) to the same host at once. Disable keep-alive so each
		// gets its own connection and the streaming up body is never queued
		// behind the never-ending down response on a pooled connection.
		client = &http.Client{Transport: &http.Transport{
			DisableCompression: true,
			DisableKeepAlives:  true,
		}}
	}
	return &Engine{cfg: cfg, client: client, reporter: randToken()}, nil
}

// Start fetches endpoints, builds the ladder, dials a path, and starts the local
// SOCKS proxy. It returns once the proxy is listening (or on fatal error).
func (e *Engine) Start(ctx context.Context) error {
	eps, err := e.endpoints()
	if err != nil {
		return err
	}
	e.ladder = brain.New(e.buildLadder(eps), e.cfg.Cooldown)
	if e.cfg.ReportURL != "" {
		e.ladder.Report = e.report
	}

	// Dial an initial path so failures surface at Start.
	if err := e.redial(ctx); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", e.cfg.SocksAddr)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.ln = ln
	e.mu.Unlock()

	go tunnel.SocksServer(ln, e) // e is the StreamOpener; it redials as needed
	return nil
}

// Stop shuts the proxy and the current channel.
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ln != nil {
		e.ln.Close()
	}
	if e.mux != nil {
		e.mux.Close()
	}
	return nil
}

// Addr reports the local SOCKS address once started.
func (e *Engine) Addr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ln == nil {
		return ""
	}
	return e.ln.Addr().String()
}

// Open satisfies tunnel.StreamOpener: it returns a mux stream, transparently
// redialing a fresh path (via the ladder) if the current channel is gone. This
// is what gives automatic failover across carriers mid-session.
func (e *Engine) Open() (io.ReadWriteCloser, error) {
	e.mu.Lock()
	m := e.mux
	e.mu.Unlock()
	if m != nil {
		if st, err := m.Open(); err == nil {
			return st, nil
		}
	}
	if err := e.redial(context.Background()); err != nil {
		return nil, err
	}
	e.mu.Lock()
	m = e.mux
	e.mu.Unlock()
	if m == nil {
		return nil, errors.New("engine: no channel after redial")
	}
	return m.Open()
}

// redial picks a working endpoint via the ladder and installs a fresh mux.
func (e *Engine) redial(ctx context.Context) error {
	conn, _, err := e.ladder.Dial(ctx, e.cfg.Network())
	if err != nil {
		return err
	}
	ic, ok := conn.(*inner.Conn)
	if !ok {
		conn.Close()
		return errors.New("engine: endpoint did not yield an inner.Conn")
	}
	m, err := inner.ClientMux(ic)
	if err != nil {
		conn.Close()
		return err
	}
	e.mu.Lock()
	old := e.mux
	e.mux = m
	e.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// endpoints returns the endpoint list, fetched+verified from AssignURL or taken
// from Config.Endpoints.
func (e *Engine) endpoints() ([]brain.PoolEndpoint, error) {
	if e.cfg.AssignURL == "" {
		if len(e.cfg.Endpoints) == 0 {
			return nil, errors.New("engine: no endpoints and no AssignURL")
		}
		return e.cfg.Endpoints, nil
	}
	a, err := brain.FetchAssignment(e.client, e.cfg.AssignURL, e.cfg.User, e.cfg.BrainPub)
	if err != nil {
		return nil, err
	}
	return a.Endpoints, nil
}

// buildLadder turns pool endpoints into ladder endpoints with a Dial closure per
// kind. v1 supports the CDN carrier and direct; skin wires in the same way.
func (e *Engine) buildLadder(eps []brain.PoolEndpoint) []brain.Endpoint {
	out := make([]brain.Endpoint, 0, len(eps))
	for _, ep := range eps {
		ep := ep
		out = append(out, brain.Endpoint{
			ID:       ep.ID,
			Label:    ep.Label,
			Priority: ep.Priority,
			Dial:     e.dialerFor(ep),
		})
	}
	return out
}

func (e *Engine) dialerFor(ep brain.PoolEndpoint) func(context.Context) (io.ReadWriteCloser, error) {
	switch ep.Kind {
	case "carrier":
		return func(ctx context.Context) (io.ReadWriteCloser, error) {
			cc, err := carrier.Dial(e.client, ep.URL)
			if err != nil {
				return nil, err
			}
			ic, err := inner.Client(cc, ep.ServerPub, e.cfg.Recipe)
			if err != nil {
				cc.Close()
				return nil, err
			}
			return ic, nil
		}
	case "skin":
		return func(ctx context.Context) (io.ReadWriteCloser, error) {
			return e.dialSkin(ep)
		}
	default: // "direct"
		return func(ctx context.Context) (io.ReadWriteCloser, error) {
			var d net.Dialer
			raw, err := d.DialContext(ctx, "tcp", ep.URL)
			if err != nil {
				return nil, err
			}
			if tc, ok := raw.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
			}
			ic, err := inner.Client(raw, ep.ServerPub, e.cfg.Recipe)
			if err != nil {
				raw.Close()
				return nil, err
			}
			return ic, nil
		}
	}
}

// dialSkin opens a "skin" endpoint: a real TLS 1.3 session to a real domain we
// own, an ordinary-looking HTTP request, then the door upgrade to the inner
// channel. The public endpoint supplies only the address and SNI; the door
// secret and ECH config come from the SIGNED recipe, never the public endpoint
// list, so no secret rides in an assignment (CLAUDE.md rule 8 / S7).
func (e *Engine) dialSkin(ep brain.PoolEndpoint) (io.ReadWriteCloser, error) {
	sni := ep.SNI
	if sni == "" {
		sni = e.cfg.Recipe.Skin.ServerName
	}
	// Clone the TLS template (or a safe default) and pin the ServerName.
	var tcfg *tls.Config
	if e.cfg.SkinTLS != nil {
		tcfg = e.cfg.SkinTLS.Clone()
	} else {
		tcfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	tcfg.ServerName = sni

	// ECH, if the recipe carries it, is applied by skin via its own clone; the
	// recipe's base64 was already validated by Recipe.Validate.
	ech, _ := base64.StdEncoding.DecodeString(e.cfg.Recipe.Skin.ECHConfigList)

	cc := &skin.ClientConfig{
		Addr:          ep.URL,
		TLS:           tcfg,
		ServerPub:     ep.ServerPub,
		Recipe:        e.cfg.Recipe,
		DoorSecret:    e.cfg.Recipe.Skin.DoorSecret,
		Path:          e.cfg.Recipe.Skin.Path,
		ECHConfigList: ech,
	}
	conn, err := cc.Dial()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// report sends one anonymous telemetry record. Best-effort; failures are ignored.
func (e *Engine) report(networkKey, epID string, ok, control bool) {
	if e.cfg.ReportURL == "" {
		return
	}
	rep := brain.Report{Reporter: e.reporter, Network: networkKey, Endpoint: epID, OK: ok, Control: control}
	body, err := json.Marshal(rep)
	if err != nil {
		return
	}
	go func() {
		req, err := http.NewRequest("POST", e.cfg.ReportURL, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if resp, err := e.client.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
}

func randToken() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
