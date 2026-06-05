// Package epee implements a minimal encoder/decoder for epee's "portable
// storage" binary format — the serialization used by Zano's daemon .bin RPC
// endpoints (and by wallet key blobs). Only the subset needed by this library
// is implemented: ordered sections, unsigned integers, booleans, strings/blobs,
// nested objects, and arrays of integers or objects.
//
// Reference: zano/contrib/epee/include/storages/portable_storage*.h
package epee

import (
	"encoding/binary"
	"fmt"
)

const (
	signatureA = 0x01011101
	signatureB = 0x01020101
	formatVer  = 1

	typeInt64  = 1
	typeInt32  = 2
	typeInt16  = 3
	typeInt8   = 4
	typeUint64 = 5
	typeUint32 = 6
	typeUint16 = 7
	typeUint8  = 8
	typeDouble = 9
	typeString = 10
	typeBool   = 11
	typeObject = 12
	typeArray  = 13

	flagArray = 0x80
)

// Section is an ordered set of named entries (an epee "section"/object). Order
// is preserved for deterministic encoding; lookup is by name.
type Section struct {
	keys   []string
	values map[string]any
}

// NewSection returns an empty Section.
func NewSection() *Section {
	return &Section{values: map[string]any{}}
}

// Set adds or replaces an entry. Supported value types: uint64, bool, string,
// []byte, *Section, []uint64, []*Section.
func (s *Section) Set(name string, v any) *Section {
	if _, ok := s.values[name]; !ok {
		s.keys = append(s.keys, name)
	}
	s.values[name] = v
	return s
}

// Get returns the raw value for name (as produced by Unmarshal or Set).
func (s *Section) Get(name string) (any, bool) {
	v, ok := s.values[name]
	return v, ok
}

// Uint64 returns a uint64-typed entry.
func (s *Section) Uint64(name string) (uint64, bool) {
	v, ok := s.values[name]
	if !ok {
		return 0, false
	}
	u, ok := v.(uint64)
	return u, ok
}

// Bytes returns a string/blob entry as bytes.
func (s *Section) Bytes(name string) ([]byte, bool) {
	v, ok := s.values[name]
	if !ok {
		return nil, false
	}
	if b, ok := v.([]byte); ok {
		return b, true
	}
	if str, ok := v.(string); ok {
		return []byte(str), true
	}
	return nil, false
}

// Sections returns an array-of-object entry.
func (s *Section) Sections(name string) ([]*Section, bool) {
	v, ok := s.values[name]
	if !ok {
		return nil, false
	}
	a, ok := v.([]*Section)
	return a, ok
}

// Marshal encodes a root section to the portable-storage binary format.
func Marshal(root *Section) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, signatureA)
	b = binary.LittleEndian.AppendUint32(b, signatureB)
	b = append(b, formatVer)
	b = appendSection(b, root)
	return b
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v<<2))
	case v <= 16383:
		return binary.LittleEndian.AppendUint16(b, uint16(v<<2)|1)
	case v <= 1073741823:
		return binary.LittleEndian.AppendUint32(b, uint32(v<<2)|2)
	default:
		return binary.LittleEndian.AppendUint64(b, (v<<2)|3)
	}
}

func appendString(b, s []byte) []byte {
	b = appendVarint(b, uint64(len(s)))
	return append(b, s...)
}

func appendSection(b []byte, s *Section) []byte {
	b = appendVarint(b, uint64(len(s.keys)))
	for _, k := range s.keys {
		b = append(b, byte(len(k)))
		b = append(b, k...)
		b = appendEntry(b, s.values[k])
	}
	return b
}

func appendEntry(b []byte, v any) []byte {
	switch x := v.(type) {
	case uint64:
		b = append(b, typeUint64)
		return binary.LittleEndian.AppendUint64(b, x)
	case bool:
		b = append(b, typeBool)
		if x {
			return append(b, 1)
		}
		return append(b, 0)
	case string:
		b = append(b, typeString)
		return appendString(b, []byte(x))
	case []byte:
		b = append(b, typeString)
		return appendString(b, x)
	case *Section:
		b = append(b, typeObject)
		return appendSection(b, x)
	case []uint64:
		b = append(b, typeUint64|flagArray)
		b = appendVarint(b, uint64(len(x)))
		for _, e := range x {
			b = binary.LittleEndian.AppendUint64(b, e)
		}
		return b
	case []*Section:
		b = append(b, typeObject|flagArray)
		b = appendVarint(b, uint64(len(x)))
		for _, e := range x {
			b = appendSection(b, e)
		}
		return b
	default:
		panic(fmt.Sprintf("epee: unsupported value type %T", v))
	}
}

// reader is a cursor over the encoded body (after the 9-byte header).
type reader struct {
	b []byte
	p int
}

func (r *reader) need(n int) error {
	if r.p+n > len(r.b) {
		return fmt.Errorf("epee: unexpected end of buffer (need %d at %d of %d)", n, r.p, len(r.b))
	}
	return nil
}

func (r *reader) byte() (byte, error) {
	if err := r.need(1); err != nil {
		return 0, err
	}
	v := r.b[r.p]
	r.p++
	return v, nil
}

func (r *reader) take(n int) ([]byte, error) {
	if err := r.need(n); err != nil {
		return nil, err
	}
	v := r.b[r.p : r.p+n]
	r.p += n
	return v, nil
}

func (r *reader) varint() (uint64, error) {
	first, err := r.byte()
	if err != nil {
		return 0, err
	}
	mask := first & 0x03
	r.p-- // re-read including the first byte
	switch mask {
	case 0:
		v, err := r.take(1)
		if err != nil {
			return 0, err
		}
		return uint64(v[0]) >> 2, nil
	case 1:
		v, err := r.take(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint16(v)) >> 2, nil
	case 2:
		v, err := r.take(4)
		if err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint32(v)) >> 2, nil
	default:
		v, err := r.take(8)
		if err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint64(v) >> 2, nil
	}
}

// Unmarshal decodes a portable-storage binary buffer into its root Section.
func Unmarshal(data []byte) (*Section, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("epee: too short (%d < 9)", len(data))
	}
	if binary.LittleEndian.Uint32(data[0:4]) != signatureA || binary.LittleEndian.Uint32(data[4:8]) != signatureB {
		return nil, fmt.Errorf("epee: bad signature")
	}
	if data[8] != formatVer {
		return nil, fmt.Errorf("epee: unknown format version %d", data[8])
	}
	r := &reader{b: data[9:]}
	return r.readSection()
}

func (r *reader) readSection() (*Section, error) {
	count, err := r.varint()
	if err != nil {
		return nil, err
	}
	s := NewSection()
	for i := uint64(0); i < count; i++ {
		nl, err := r.byte()
		if err != nil {
			return nil, err
		}
		name, err := r.take(int(nl))
		if err != nil {
			return nil, err
		}
		v, err := r.readEntry()
		if err != nil {
			return nil, err
		}
		s.Set(string(name), v)
	}
	return s, nil
}

func (r *reader) readEntry() (any, error) {
	t, err := r.byte()
	if err != nil {
		return nil, err
	}
	if t&flagArray != 0 {
		return r.readArray(t &^ flagArray)
	}
	return r.readValue(t)
}

func (r *reader) readArray(base byte) (any, error) {
	count, err := r.varint()
	if err != nil {
		return nil, err
	}
	if base == typeObject {
		out := make([]*Section, 0, count)
		for i := uint64(0); i < count; i++ {
			sec, err := r.readSection()
			if err != nil {
				return nil, err
			}
			out = append(out, sec)
		}
		return out, nil
	}
	out := make([]any, 0, count)
	for i := uint64(0); i < count; i++ {
		v, err := r.readValue(base)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r *reader) readValue(t byte) (any, error) {
	switch t {
	case typeUint64, typeInt64:
		v, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return binary.LittleEndian.Uint64(v), nil
	case typeUint32, typeInt32:
		v, err := r.take(4)
		if err != nil {
			return nil, err
		}
		return uint64(binary.LittleEndian.Uint32(v)), nil
	case typeUint16, typeInt16:
		v, err := r.take(2)
		if err != nil {
			return nil, err
		}
		return uint64(binary.LittleEndian.Uint16(v)), nil
	case typeUint8, typeInt8:
		v, err := r.byte()
		if err != nil {
			return nil, err
		}
		return uint64(v), nil
	case typeBool:
		v, err := r.byte()
		if err != nil {
			return nil, err
		}
		return v != 0, nil
	case typeDouble:
		v, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return binary.LittleEndian.Uint64(v), nil // raw bits; not needed by us
	case typeString:
		n, err := r.varint()
		if err != nil {
			return nil, err
		}
		v, err := r.take(int(n))
		if err != nil {
			return nil, err
		}
		// return a copy as []byte so callers get exact bytes (may be binary)
		out := make([]byte, len(v))
		copy(out, v)
		return out, nil
	case typeObject:
		return r.readSection()
	default:
		return nil, fmt.Errorf("epee: unsupported value type %d", t)
	}
}
