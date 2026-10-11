// SPDX-License-Identifier: MPL-2.0

package brain

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
)

// Staged wraps a dial error with the phase it failed in ("tcp", "tls", "door",
// "inner", "data"), so the ladder can attach it to anonymous telemetry. This is
// a research signal — WHERE a block happens, e.g. a TLS reset vs an inner-channel
// drop — not a per-user fact. A nil err stays nil; an empty stage returns err
// unchanged so callers that don't classify the phase cost nothing.
func Staged(stage string, err error) error {
	if err == nil || stage == "" {
		return err
	}
	return &stagedError{stage: stage, err: err}
}

// StageOf returns the phase recorded by Staged anywhere in err's chain, or "".
func StageOf(err error) string {
	var se *stagedError
	if errors.As(err, &se) {
		return se.stage
	}
	return ""
}

type stagedError struct {
	stage string
	err   error
}

func (e *stagedError) Error() string { return e.stage + ": " + e.err.Error() }
func (e *stagedError) Unwrap() error { return e.err }

// ReasonOf classifies WHY a dial failed into a small, FIXED vocabulary — so the
// dashboard can show "why didn't it connect?", not just where. It deliberately
// never puts the raw error text on the wire: an error string can carry a
// destination host, a path or other identifying detail (CLAUDE.md rule 6), so we
// map to a closed set of codes instead:
//
//	timeout     — no answer in time (classic silent drop / throttle)
//	reset       — connection reset / broken pipe (an active RST, a DPI signature)
//	refused     — TCP refused (nothing listening / port blocked)
//	unreachable — no route / network unreachable
//	closed      — peer hung up mid-handshake (EOF)
//	tls         — TLS handshake or alert failure (fingerprint/SNI rejection)
//	cert        — certificate verification failed
//	protocol    — door/inner rejected us (server served the cover site, or the
//	              Noise handshake failed) — i.e. reached TLS but not the tunnel
//	canceled    — the attempt was canceled (app gave up / switched)
//	other       — anything unclassified
//
// A nil error returns "".
func ReasonOf(err error) string {
	if err == nil {
		return ""
	}

	// Cancellation / timeout first: they can wrap any lower-level cause and are
	// the most actionable signal (a silent drop vs an active block).
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}

	// Syscall-level connection outcomes.
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "closed"
	}

	// TLS specifics.
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "cert"
	}
	var recErr tls.RecordHeaderError
	if errors.As(err, &recErr) {
		return "tls"
	}
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return "tls"
	}

	// Reached a working TLS session but the tunnel refused us: the skin marks
	// these phases, and they mean "cover site served / Noise rejected".
	switch StageOf(err) {
	case "door", "inner":
		return "protocol"
	}

	// Last resort: recognise a few well-known phrasings, but still return only a
	// fixed code — the raw text never leaves the device. Unwrap to the root first
	// so a stage prefix (e.g. "tls: ") can't masquerade as the cause.
	root := err
	for {
		u := errors.Unwrap(root)
		if u == nil {
			break
		}
		root = u
	}
	s := strings.ToLower(root.Error())
	switch {
	case strings.Contains(s, "connection reset"), strings.Contains(s, "broken pipe"):
		return "reset"
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "no route to host"), strings.Contains(s, "unreachable"):
		return "unreachable"
	case strings.Contains(s, "timeout"), strings.Contains(s, "timed out"), strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "eof"):
		return "closed"
	case strings.Contains(s, "tls"), strings.Contains(s, "handshake"), strings.Contains(s, "certificate"):
		return "tls"
	}
	return "other"
}
