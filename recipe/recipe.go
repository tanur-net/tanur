// SPDX-License-Identifier: MPL-2.0

// Package recipe defines a Tanur "recipe": the set of distributions and
// parameters that make one session behave differently from another on the wire.
//
// A recipe never carries fixed on-wire constants. It carries *distributions*;
// the shaper samples concrete values from them using a per-session nonce, so
// two sessions of the same recipe still differ. This is the unit the "factory"
// produces and the "brain" retires when a variant is burned.
//
// Design doc: docs/inner-protocol-v0.md section 2.
package recipe

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// Recipe is one named, versioned variant. It is the data the factory generates
// and the brain hands to a client. It is signed before shipping; signature
// handling lives outside this package.
type Recipe struct {
	// ID is a stable identifier the brain uses to say "retire this variant".
	ID string `json:"id"`
	// Version lets a client reject a recipe it is too old to understand.
	Version int `json:"version"`

	// Skin configures the outer HTTPS appearance.
	Skin SkinParams `json:"skin"`
	// Frame configures the obfuscated length distribution of inner frames.
	Frame IntDist `json:"frame"`
	// Burst is how many frames are sent back-to-back before an inter-burst gap.
	// Real browsing and streaming move data in bursts, not as a steady drip; and
	// a per-frame pause (Burst=1 with a large Gap) collapses throughput on a
	// high-latency link. Min must be >= 1. (docs/dpi-and-shaper-requirements.md S3)
	Burst IntDist `json:"burst"`
	// Gap is the pause in milliseconds BEFORE each new burst. This is the
	// "streaming clock": the visible pacing an observer sees between chunks.
	Gap IntDist `json:"gap"`
	// Pause is an optional small per-frame jitter in milliseconds WITHIN a burst.
	// Usually 0; a few ms can blur exact frame timing without killing throughput.
	Pause IntDist `json:"pause"`
	// Pad configures how many padding bytes may be added to a frame.
	Pad IntDist `json:"pad"`
	// Open is the opening-window policy: the first few frames are kept small, so
	// the early UPSTREAM stays under the operator's initial-upload trip (e.g.
	// Irancell's ~6-packet upload limit, field intel from Iran)
	// and the flow's start also looks like a real TLS handshake plus a small
	// request before bulk data. Zero value = no opening window (back-compatible).
	Open OpenParams `json:"open"`
	// Session bounds the whole session so no recipe runs forever identically.
	Session SessionBounds `json:"session"`
}

// OpenParams caps the opening frames of a session. During the window the shaper
// holds each frame's on-wire size at or below Cap bytes, so the early upload is
// a handful of small packets rather than an immediate bulk burst.
type OpenParams struct {
	// Frames is how many initial frames are capped. 0 disables the window.
	Frames int `json:"frames"`
	// Cap is the maximum on-wire bytes (payload + padding) per opening frame.
	Cap int `json:"cap"`
}

// SkinParams are the knobs for the outer, visible HTTPS layer.
type SkinParams struct {
	// ServerName is the SNI / certificate domain. Must be a real domain we own
	// that actually serves a site on the same host.
	ServerName string `json:"server_name"`
	// ClientHelloID names the browser fingerprint profile the client mimics
	// (resolved against the uTLS table at dial time, not here).
	ClientHelloID string `json:"client_hello_id"`
	// Path is the HTTP request path used to reach the door.
	Path string `json:"path"`
	// ALPN is the advertised protocol list; "http/1.1" only for v0.
	ALPN []string `json:"alpn"`
	// ECHConfigList is an optional base64 (std) ECHConfigList. When set, the skin
	// client encrypts its ClientHello so the real SNI never appears in clear.
	// Field intel shows ECH is a working bypass on MCI where plain SNI is read
	// (observed in field intel from Iran). Empty = no ECH.
	ECHConfigList string `json:"ech_config_list,omitempty"`
	// DoorSecret is the per-deployment shared secret the skin client proves it
	// knows to be upgraded from the real website to the inner channel. It is not
	// a tunnel credential (that is the Noise handshake), only a quiet unforgeable
	// "this one is for me" signal; it rides in the signed recipe, not in the
	// public endpoint list. Empty is allowed for carrier/direct recipes.
	DoorSecret string `json:"door_secret,omitempty"`
}

// SessionBounds cap a session so it cannot become a long symmetric tunnel that
// looks nothing like real browsing. Zero means "unbounded" and is disallowed by
// Validate for the duration/byte caps, so a recipe must choose a bound.
type SessionBounds struct {
	MaxSeconds int   `json:"max_seconds"`
	MaxBytes   int64 `json:"max_bytes"`
}

// IntDist is a bounded integer distribution. v0 keeps it deliberately simple: a
// closed interval [Min, Max] sampled uniformly. The sampler is seeded per
// session, so the *choice* of value is unpredictable to an observer but
// reproducible given the nonce. Richer shapes (e.g. mixtures) can be added
// behind the same Sample contract without changing callers.
type IntDist struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// Validate reports the first problem with a distribution, or nil.
func (d IntDist) Validate(name string) error {
	if d.Min < 0 {
		return fmt.Errorf("%s: min must be >= 0, got %d", name, d.Min)
	}
	if d.Max < d.Min {
		return fmt.Errorf("%s: max (%d) must be >= min (%d)", name, d.Max, d.Min)
	}
	return nil
}

// Span is the number of distinct values the distribution can take.
func (d IntDist) Span() int { return d.Max - d.Min + 1 }

var (
	// ErrNoID is returned when a recipe lacks an identifier.
	ErrNoID = errors.New("recipe: empty id")
	// ErrBadVersion is returned for a non-positive version.
	ErrBadVersion = errors.New("recipe: version must be >= 1")
	// ErrNoServerName is returned when the skin has no SNI/cert domain.
	ErrNoServerName = errors.New("recipe: skin.server_name is empty")
	// ErrUnbounded is returned when a session has no duration or byte cap.
	ErrUnbounded = errors.New("recipe: session must set max_seconds and max_bytes > 0")
)

// Validate checks every field and returns the first problem, or nil. A recipe
// that fails Validate must never be dialed: an invalid recipe is how a fixed
// on-wire constant or an unbounded tunnel sneaks in.
func (r Recipe) Validate() error {
	if r.ID == "" {
		return ErrNoID
	}
	if r.Version < 1 {
		return ErrBadVersion
	}
	if r.Skin.ServerName == "" {
		return ErrNoServerName
	}
	if len(r.Skin.ALPN) == 0 {
		return fmt.Errorf("recipe: skin.alpn must list at least one protocol")
	}
	if r.Skin.ECHConfigList != "" {
		if _, err := base64.StdEncoding.DecodeString(r.Skin.ECHConfigList); err != nil {
			return fmt.Errorf("recipe: skin.ech_config_list is not valid base64: %w", err)
		}
	}
	for _, d := range []struct {
		name string
		dist IntDist
	}{
		{"frame", r.Frame},
		{"burst", r.Burst},
		{"gap", r.Gap},
		{"pause", r.Pause},
		{"pad", r.Pad},
	} {
		if err := d.dist.Validate(d.name); err != nil {
			return err
		}
	}
	// A frame of length zero carries nothing; the obfuscated minimum must be
	// positive so every frame moves at least one byte of real payload budget.
	if r.Frame.Min < 1 {
		return fmt.Errorf("recipe: frame.min must be >= 1, got %d", r.Frame.Min)
	}
	// A burst must contain at least one frame, or the shaper makes no progress.
	if r.Burst.Min < 1 {
		return fmt.Errorf("recipe: burst.min must be >= 1, got %d", r.Burst.Min)
	}
	// An opening window must be able to carry at least one byte per frame, or it
	// would stall the session instead of merely keeping the start small.
	if r.Open.Frames < 0 {
		return fmt.Errorf("recipe: open.frames must be >= 0, got %d", r.Open.Frames)
	}
	if r.Open.Frames > 0 && r.Open.Cap < 1 {
		return fmt.Errorf("recipe: open.cap must be >= 1 when open.frames > 0, got %d", r.Open.Cap)
	}
	if r.Session.MaxSeconds <= 0 || r.Session.MaxBytes <= 0 {
		return ErrUnbounded
	}
	return nil
}
