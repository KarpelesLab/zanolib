package zanobase

import (
	"encoding/hex"
	"encoding/json"
	"io"

	"filippo.io/edwards25519"
)

// Point wraps an edwards25519.Point with JSON marshaling and io.WriterTo/ReaderFrom support.
type Point struct {
	*edwards25519.Point
}

// MarshalJSON encodes the point as a hex-encoded JSON string, or null if unset.
func (p *Point) MarshalJSON() ([]byte, error) {
	if p.Point == nil {
		return []byte("null"), nil
	}
	return json.Marshal(hex.EncodeToString(p.Point.Bytes()))
}

// WriteTo writes the 32-byte compressed point encoding to w.
func (p *Point) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(p.Point.Bytes())
	return int64(n), err
}

// ReadFrom reads 32 bytes from r and decodes them as a compressed Edwards point.
func (p *Point) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 32)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return int64(n), err
	}
	if p.Point == nil {
		p.Point = new(edwards25519.Point)
	}
	_, err = p.Point.SetBytes(buf)
	return int64(n), err
}
