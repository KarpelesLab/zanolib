package zanobase

import (
	"encoding/hex"
	"encoding/json"
	"io"

	"filippo.io/edwards25519"
)

// Scalar wraps an edwards25519.Scalar with JSON marshaling and io.WriterTo/ReaderFrom support.
type Scalar struct {
	*edwards25519.Scalar
}

// MarshalJSON encodes the scalar as a hex-encoded JSON string, or null if unset.
func (s *Scalar) MarshalJSON() ([]byte, error) {
	if s.Scalar == nil {
		return []byte("null"), nil
	}
	return json.Marshal(hex.EncodeToString(s.Scalar.Bytes()))
}

// WriteTo writes the 32-byte canonical scalar encoding to w.
func (s *Scalar) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(s.Scalar.Bytes())
	return int64(n), err
}

// ReadFrom reads 32 bytes from r and decodes them as a canonical scalar.
func (s *Scalar) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 32)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return int64(n), err
	}
	if s.Scalar == nil {
		s.Scalar = new(edwards25519.Scalar)
	}
	_, err = s.Scalar.SetCanonicalBytes(buf)
	return int64(n), err
}
