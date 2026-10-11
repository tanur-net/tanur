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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	// Bundle is a signed recipe+assignment the host already fetched through its
	// own resilient, authenticated network stack (fronts, pinning, token) — the
	// recommended path on a censored line, where a plain engine fetch would be
	// the weakest link. When set, the engine verifies it against BrainPub and
	// uses it, fetching nothing. It is the JSON {"recipe":...,"assignment":...}.
	Bundle []byte
	// AssignURL is where to fetch the signed bundle itself, for hosts that do
	// not pre-fetch. Used only when Bundle is empty. If both are empty, Endpoints
	// is used directly.
	AssignURL string
	// BrainPub verifies the signed recipe and assignment. Required with Bundle
	// or AssignURL.
	BrainPub ed25519.PublicKey
	// Endpoints, when AssignURL is empty, is the endpoint list to use directly.
	Endpoints []brain.PoolEndpoint
	// Recipe shapes the inner channel (one recipe for all endpoints in v1).
	Recipe recipe.Recipe
	// SocksAddr is the local SOCKS5 listen address.
	SocksAddr string
	// SocksUser and SocksPass, when SocksUser is non-empty, require RFC 1929
	// username/password login on the local SOCKS port. A host app that puts a
	// shared tun2socks (e.g. hev-socks5-tunnel on Android) in front of the port
	// sets these so no other app on the device can borrow it; left empty the
	// port is no-auth, which is all our own in-process tun2socks (iOS) needs.
	SocksUser string
	SocksPass string
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
	meter    *tunnel.Meter // app bytes carried by the local SOCKS proxy
	// recipe is the effective shaping recipe (with skin door). It starts as
	// Config.Recipe and is replaced by the signed recipe the brain serves when
	// AssignURL is set, so the door and shaping rotate from the server, not the
	// hardcoded client. See endpoints().
	recipe recipe.Recipe

	// Telemetry is buffered and flushed as a BATCH on a jittered timer (and on
	// Stop), never one POST per dial: a per-dial phone-home at handshake time
	// would hand the censor a timing signature (iran-circumvention-brief). The
	// batch rides the same fronted host as the tunnel. See report/flushReports.
	repMu       sync.Mutex
	repBuf      []brain.Report
	repRotate   time.Time // when the reporter token was last rotated
	repStop     chan struct{}
	repStopOnce sync.Once

	mu  sync.Mutex
	mux *inner.Mux
	ln  net.Listener
}

// Up and Down report the cumulative application bytes the local SOCKS proxy has
// carried out of and into the device since Start. A host app reads them for its
// traffic display.
func (e *Engine) Up() int64   { return e.meter.Up() }
func (e *Engine) Down() int64 { return e.meter.Down() }

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
	return &Engine{cfg: cfg, client: client, reporter: randToken(), repRotate: time.Now(), meter: &tunnel.Meter{}, recipe: cfg.Recipe}, nil
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
		e.repStop = make(chan struct{})
		go e.reportLoop()
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

	// e is the StreamOpener; it redials as needed. The meter counts the app
	// bytes it carries for the host's traffic display. With credentials set, the
	// local port demands RFC 1929 login (Android, shared tun2socks); without,
	// it is no-auth (iOS, our own in-process tun2socks).
	go tunnel.SocksServerMetered(ln, e, e.cfg.SocksUser, e.cfg.SocksPass, e.meter)
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
	// Signal the telemetry flusher to send a final batch and exit. Non-blocking:
	// the final flush runs in that goroutine, not here.
	if e.repStop != nil {
		e.repStopOnce.Do(func() { close(e.repStop) })
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

// endpoints returns the endpoint list. With AssignURL set it fetches a signed
// bundle from the brain — a signed recipe (with the skin door) and a signed
// per-user assignment (the endpoints) — verifies both against BrainPub, and
// adopts the served recipe so the door and shaping come from the server, not
// the client. Without AssignURL it uses Config.Endpoints (and the client's
// Config.Recipe), the path the hardcoded beta and the tests take.
func (e *Engine) endpoints() ([]brain.PoolEndpoint, error) {
	// A host-fetched bundle (recommended) or a bundle the engine fetches itself.
	if len(e.cfg.Bundle) > 0 {
		r, eps, err := parseBundle(e.cfg.Bundle, e.cfg.BrainPub, e.cfg.User, time.Now())
		if err != nil {
			return nil, err
		}
		e.recipe = r
		return eps, nil
	}
	if e.cfg.AssignURL != "" {
		r, eps, err := e.fetchBundle()
		if err != nil {
			return nil, err
		}
		e.recipe = r
		return eps, nil
	}
	if len(e.cfg.Endpoints) == 0 {
		return nil, errors.New("engine: no Bundle, no AssignURL and no Endpoints")
	}
	return e.cfg.Endpoints, nil
}

// brainBundle is the brain's reply: a signed recipe and a signed assignment,
// each base64 of its own canonical signed bytes. They are separate documents
// with separate lifetimes — the recipe (with the door) rotates per deployment,
// the assignment per user — so neither is embedded in the other, and no secret
// ever rides in the assignment (CLAUDE.md rule 8 / S7).
type brainBundle struct {
	Recipe     []byte `json:"recipe"`     // recipe.Seal output
	Assignment []byte `json:"assignment"` // brain.Sign output
}

// fetchBundle gets and verifies the signed recipe + assignment from the brain.
func (e *Engine) fetchBundle() (recipe.Recipe, []brain.PoolEndpoint, error) {
	// Build the URL with the query API so a user value is always encoded and an
	// AssignURL that already carries a query is not corrupted by string-concat.
	u, err := url.Parse(e.cfg.AssignURL)
	if err != nil {
		return recipe.Recipe{}, nil, err
	}
	q := u.Query()
	q.Set("user", e.cfg.User)
	u.RawQuery = q.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return recipe.Recipe{}, nil, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return recipe.Recipe{}, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return recipe.Recipe{}, nil, fmt.Errorf("engine: brain http %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return recipe.Recipe{}, nil, err
	}
	return parseBundle(data, e.cfg.BrainPub, e.cfg.User, time.Now())
}

// parseBundle verifies a signed recipe+assignment bundle against pub and returns
// the recipe and its endpoints. The same code checks a bundle the host fetched
// and one the engine fetched, so the trust anchor (BrainPub) is enforced on both
// paths and a tampered or wrong-key bundle is rejected before any dial.
func parseBundle(data []byte, pub ed25519.PublicKey, expectedUser string, now time.Time) (recipe.Recipe, []brain.PoolEndpoint, error) {
	var b brainBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return recipe.Recipe{}, nil, fmt.Errorf("engine: brain reply: %w", err)
	}
	r, err := recipe.Open(b.Recipe, pub)
	if err != nil {
		return recipe.Recipe{}, nil, err
	}
	a, err := brain.OpenAssignment(b.Assignment, pub)
	if err != nil {
		return recipe.Recipe{}, nil, err
	}
	// A valid signature proves provenance only; also require the assignment to be
	// fresh, for this user, and made of dialable endpoints before trusting it.
	if err := a.Validate(expectedUser, now, 0); err != nil {
		return recipe.Recipe{}, nil, err
	}
	return r, a.Endpoints, nil
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
				return nil, brain.Staged("carrier", err)
			}
			ic, err := inner.Client(cc, ep.ServerPub, e.recipe)
			if err != nil {
				cc.Close()
				return nil, brain.Staged("inner", err)
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
				return nil, brain.Staged("tcp", err)
			}
			if tc, ok := raw.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
			}
			ic, err := inner.Client(raw, ep.ServerPub, e.recipe)
			if err != nil {
				raw.Close()
				return nil, brain.Staged("inner", err)
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
		sni = e.recipe.Skin.ServerName
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
	ech, _ := base64.StdEncoding.DecodeString(e.recipe.Skin.ECHConfigList)

	// Outer handshake mimics a real browser (uTLS). Default to Chrome when the
	// recipe does not name a profile, so a shipped client never falls back to the
	// distinctive crypto/tls ClientHello that fingerprint DPI drops.
	helloID := e.recipe.Skin.ClientHelloID
	if helloID == "" {
		helloID = "chrome"
	}

	cc := &skin.ClientConfig{
		Addr:          ep.URL,
		TLS:           tcfg,
		ServerPub:     ep.ServerPub,
		Recipe:        e.recipe,
		DoorSecret:    e.recipe.Skin.DoorSecret,
		Path:          e.recipe.Skin.Path,
		ECHConfigList: ech,
		ClientHelloID: helloID,
	}
	conn, err := cc.Dial()
	if err != nil {
		// skin.DialStage tells us which phase failed (tcp/tls/door/inner) so
		// telemetry can distinguish e.g. an SNI/TLS reset from an inner block.
		return nil, brain.Staged(skin.DialStage(err), err)
	}
	return conn, nil
}

// reportFlushInterval is the base period between telemetry batch flushes; the
// actual wait is jittered around it so the flush is not a regular beacon.
const reportFlushInterval = 60 * time.Second

// reportBufMax caps buffered reports; reaching it triggers an early flush so the
// buffer (and the batch body) stay bounded.
const reportBufMax = 64

// report buffers one anonymous telemetry record. It never touches the network
// (so it can't block or delay a dial); the buffer is flushed as a batch by
// reportLoop. The operator key is set server-side from the source IP, so the
// networkKey the client would send is not relied upon (left here for the
// fallback path on platforms that can read it).
func (e *Engine) report(networkKey, epID string, ok, control bool, stage, reason string) {
	if e.cfg.ReportURL == "" {
		return
	}
	e.repMu.Lock()
	// Read the reporter under the lock: it rotates (see maybeRotateReporter), so
	// reports within one epoch share a token for the collector's distinct-reporter
	// dedup, while reports across epochs are unlinkable.
	rep := brain.Report{Reporter: e.reporter, Network: networkKey, Endpoint: epID, OK: ok, Control: control, Stage: stage, Reason: reason}
	e.repBuf = append(e.repBuf, rep)
	full := len(e.repBuf) >= reportBufMax
	e.repMu.Unlock()
	if full {
		go e.flushReports()
	}
}

// reporterEpoch bounds how long one reporter token is used. It is far longer than
// any reasonable collector dedup/burn window (seconds-to-minutes), so rotating
// does not inflate the distinct-reporter count, yet it stops a long-lived engine
// from tagging every report over hours/days with one linkable token.
const reporterEpoch = 30 * time.Minute

// maybeRotateReporter rolls the reporter token once an epoch has passed.
func (e *Engine) maybeRotateReporter() {
	e.repMu.Lock()
	if time.Since(e.repRotate) >= reporterEpoch {
		e.reporter = randToken()
		e.repRotate = time.Now()
	}
	e.repMu.Unlock()
}

// reportLoop flushes the telemetry buffer as a batch on a jittered timer, and
// once more on Stop. Runs only when ReportURL is set.
func (e *Engine) reportLoop() {
	for {
		select {
		case <-time.After(jitteredInterval(reportFlushInterval)):
			e.flushReports()
			e.maybeRotateReporter()
		case <-e.repStop:
			e.flushReports() // final flush
			return
		}
	}
}

// flushReports sends the buffered reports as one batch. Best-effort: on any
// failure the batch is dropped rather than retried, since a retry storm would
// itself be a signature. Safe to call concurrently (the buffer swap is atomic).
func (e *Engine) flushReports() {
	e.repMu.Lock()
	if len(e.repBuf) == 0 {
		e.repMu.Unlock()
		return
	}
	batch := e.repBuf
	e.repBuf = nil
	e.repMu.Unlock()

	body, err := json.Marshal(batch)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", e.cfg.ReportURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := e.client.Do(req); err == nil {
		resp.Body.Close()
	}
}

// jitteredInterval returns a wait uniformly in [base/2, 3*base/2), so the flush
// cadence is not a fixed-period beacon.
func jitteredInterval(base time.Duration) time.Duration {
	var b [7]byte // 56 bits: always a non-negative int64
	rand.Read(b[:])
	var n int64
	for _, x := range b {
		n = n<<8 | int64(x)
	}
	return base/2 + time.Duration(n%int64(base))
}

func randToken() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
