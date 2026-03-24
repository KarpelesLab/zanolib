package zanobase

import (
	"errors"
	"io"

	"github.com/KarpelesLab/rc"
)

// Varint is a variable-length encoded unsigned integer, compatible with the
// varint format used by Zano/CryptoNote.
type Varint uint64

// Bytes returns the varint-encoded representation.
func (v Varint) Bytes() []byte {
	return VarintAppendUint64(nil, uint64(v))
}

// ReadFrom reads a varint from r.
func (v *Varint) ReadFrom(r io.Reader) (int64, error) {
	rc := rc.New(r)
	n, err := VarintReadUint64(rc)
	if err != nil {
		return rc.Error64(err)
	}
	*v = Varint(n)
	return rc.Ret64()
}

// VarintPackedSize returns the number of bytes needed to encode v as a varint.
func VarintPackedSize(v uint64) int {
	switch {
	case v <= 0x7f:
		return 1
	case v <= 0x3fff:
		return 2
	case v <= 0x1f_ffff:
		return 3
	case v <= 0xfff_ffff:
		return 4
	case v <= 0x7_ffff_ffff:
		return 5
	case v <= 0x3ff_ffff_ffff:
		return 6
	case v <= 0x1_ffff_ffff_ffff:
		return 7
	default:
		return 8
	}
}

// VarintAppendUint64 appends the varint encoding of v to buf and returns the result.
func VarintAppendUint64(buf []byte, v uint64) []byte {
	for v > 0x80 {
		buf = append(buf, byte(v&0x7f)|0x80)
		v >>= 7
	}
	buf = append(buf, byte(v))
	return buf
}

// VarintTakeUint64 decodes a varint from the start of buf and returns
// the remaining bytes, the decoded value, and any error.
func VarintTakeUint64(buf []byte) ([]byte, uint64, error) {
	var v uint64
	var offt int
	for len(buf) > 0 && buf[0]&0x80 == 0x80 {
		v |= (uint64(buf[0]) & 0x7f) << offt
		offt += 7
		buf = buf[1:]
	}
	if len(buf) == 0 {
		return buf, v, errors.New("buffer underrun while decoding varint")
	}
	v |= uint64(buf[0]) << offt
	return buf[1:], v, nil
}

// VarintReadUint64 reads and decodes a varint from r.
func VarintReadUint64(r io.ByteReader) (uint64, error) {
	var v uint64
	var offt int
	for {
		n, err := r.ReadByte()
		if err != nil {
			return v, notEOF(err)
		}
		v |= (uint64(n) & 0x7f) << offt
		offt += 7
		if n&0x80 == 0 {
			return v, nil
		}
	}
}

func notEOF(e error) error {
	if errors.Is(e, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return e
}
