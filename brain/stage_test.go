// SPDX-License-Identifier: MPL-2.0

package brain

import (
	"context"
	"errors"
	"io"
	"syscall"
	"testing"
)

// ReasonOf must map real dial errors to the fixed, non-identifying vocabulary,
// unwrapping any Staged() prefix so a stage name never masquerades as the cause.
func TestReasonOf(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"timeout-ctx", context.DeadlineExceeded, "timeout"},
		{"canceled", context.Canceled, "canceled"},
		{"refused", syscall.ECONNREFUSED, "refused"},
		{"reset", syscall.ECONNRESET, "reset"},
		{"broken-pipe", syscall.EPIPE, "reset"},
		{"host-unreachable", syscall.EHOSTUNREACH, "unreachable"},
		{"net-unreachable", syscall.ENETUNREACH, "unreachable"},
		{"eof", io.EOF, "closed"},
		{"unexpected-eof", io.ErrUnexpectedEOF, "closed"},
		// Staged wrapping must not change the classification.
		{"staged-reset", Staged("tls", syscall.ECONNRESET), "reset"},
		{"staged-timeout", Staged("tcp", context.DeadlineExceeded), "timeout"},
		// Reached TLS but the tunnel refused us -> protocol.
		{"door-protocol", Staged("door", errors.New("served cover site")), "protocol"},
		{"inner-protocol", Staged("inner", errors.New("noise handshake failed")), "protocol"},
		// Unknown stays "other", and never leaks the raw text.
		{"unknown", Staged("tls", errors.New("weird internal state")), "other"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ReasonOf(c.err); got != c.want {
				t.Fatalf("ReasonOf(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}

// A timeout wrapped as a net.Error (what the stdlib actually returns) must be
// read as "timeout" even through a Staged prefix.
func TestReasonOfNetTimeout(t *testing.T) {
	err := Staged("tls", timeoutErr{})
	if got := ReasonOf(err); got != "timeout" {
		t.Fatalf("net timeout: got %q, want timeout", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
