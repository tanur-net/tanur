// SPDX-License-Identifier: MPL-2.0

package inner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// A session's byte stream is carried as a sequence of AEAD frames. Each frame on
// the wire is:
//
//	[2 bytes: ciphertext length N][N bytes: AEAD ciphertext]
//
// The plaintext inside each frame is:
//
//	[2 bytes: payload length P][P bytes: payload][padding]
//
// So the receiver can recover exactly P real bytes and discard the padding. The
// padding and the per-frame size come from the shaper, which is what makes two
// sessions of one recipe differ. The length prefix is plaintext (standard for a
// framed secure stream) and sits inside the outer TLS skin; concealment comes
// from size variation and padding, not from hiding the prefix.

const (
	maxFramePlaintext = 65519 // 65535 - 16-byte AEAD tag
	lenPrefix         = 2
)

var (
	// ErrFrameTooLarge is returned when a caller asks to write more than one
	// frame can hold. Callers should chunk via the shaper instead.
	ErrFrameTooLarge = errors.New("inner: frame plaintext exceeds maximum")
	// ErrShortFrame is returned when a decrypted frame is malformed.
	ErrShortFrame = errors.New("inner: malformed frame")
)

// WriteFrame encrypts payload with pad bytes of padding and writes one framed
// record to w. pad bytes of zero padding are appended; their only purpose is to
// make the on-wire length not equal the payload length.
func (s *Session) WriteFrame(w io.Writer, payload []byte, pad int) error {
	if pad < 0 {
		pad = 0
	}
	plainLen := lenPrefix + len(payload) + pad
	if plainLen > maxFramePlaintext {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, plainLen)
	}
	plain := make([]byte, lenPrefix+len(payload)+pad)
	binary.BigEndian.PutUint16(plain[:lenPrefix], uint16(len(payload)))
	copy(plain[lenPrefix:], payload)
	// padding stays zero; it is inside the AEAD so an observer sees only random
	// ciphertext of a varied length.

	ct, err := s.send.Encrypt(nil, nil, plain)
	if err != nil {
		return err
	}
	// Write the length prefix and ciphertext in ONE Write. Splitting them into
	// two writes puts a 2-byte segment on the wire ahead of the body, which on a
	// high-latency link interacts badly with Nagle's algorithm and delayed ACKs
	// and collapses throughput. A single write keeps each frame one segment.
	out := make([]byte, lenPrefix+len(ct))
	binary.BigEndian.PutUint16(out[:lenPrefix], uint16(len(ct)))
	copy(out[lenPrefix:], ct)
	_, err = w.Write(out)
	return err
}

// ReadFrame reads one framed record from r, decrypts it, and returns the payload
// with padding stripped.
func (s *Session) ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [lenPrefix]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	ct := make([]byte, n)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, err
	}
	plain, err := s.recv.Decrypt(nil, nil, ct)
	if err != nil {
		return nil, err
	}
	if len(plain) < lenPrefix {
		return nil, ErrShortFrame
	}
	p := int(binary.BigEndian.Uint16(plain[:lenPrefix]))
	if lenPrefix+p > len(plain) {
		return nil, ErrShortFrame
	}
	return plain[lenPrefix : lenPrefix+p], nil
}
