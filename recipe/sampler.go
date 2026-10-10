// SPDX-License-Identifier: MPL-2.0

package recipe

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
)

// Sampler draws concrete values from a recipe's distributions for one session.
//
// It is seeded from a 32-byte session nonce so that: (a) an on-path observer
// cannot predict the sequence of sizes and pauses, yet (b) given the same nonce
// the sequence is reproducible, which makes the behaviour testable and lets the
// two ends stay in agreement where they must.
//
// The stream is a ChaCha20 keystream over a zero plaintext: a standard,
// well-reviewed CSPRNG construction. We do NOT invent randomness here.
type Sampler struct {
	cipher *chacha20.Cipher
	buf    [8]byte
}

// NonceLen is the required length of a session nonce seed.
const NonceLen = 32

// ErrBadNonce is returned when the seed is not NonceLen bytes.
var ErrBadNonce = errors.New("recipe: session nonce must be 32 bytes")

// NewSampler builds a sampler for one session from a 32-byte nonce.
func NewSampler(nonce []byte) (*Sampler, error) {
	if len(nonce) != NonceLen {
		return nil, ErrBadNonce
	}
	// chacha20 wants a 32-byte key and a 12-byte nonce. We use the session
	// nonce as the key and a fixed all-zero cipher nonce: the key is the
	// per-session secret, so a constant cipher nonce is safe for a one-shot
	// keystream and keeps the construction simple.
	var zero [chacha20.NonceSize]byte
	c, err := chacha20.NewUnauthenticatedCipher(nonce, zero[:])
	if err != nil {
		return nil, err
	}
	return &Sampler{cipher: c}, nil
}

// next returns the next 64-bit value from the keystream.
func (s *Sampler) next() uint64 {
	for i := range s.buf {
		s.buf[i] = 0
	}
	s.cipher.XORKeyStream(s.buf[:], s.buf[:])
	return binary.LittleEndian.Uint64(s.buf[:])
}

// Int draws one value from dist, uniform over [Min, Max]. It uses rejection
// sampling to avoid modulo bias, so the distribution is exactly uniform.
func (s *Sampler) Int(dist IntDist) int {
	span := uint64(dist.Span())
	if span == 1 {
		return dist.Min
	}
	// Largest multiple of span that fits in uint64; reject above it.
	limit := (^uint64(0) / span) * span
	for {
		v := s.next()
		if v < limit {
			return dist.Min + int(v%span)
		}
	}
}
