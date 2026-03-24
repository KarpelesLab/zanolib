package zanobase

import (
	"fmt"
	"io"

	"github.com/KarpelesLab/rc"
)

// ReadVarBytes reads a varint-prefixed byte slice from r.
// The maximum length is 4096 bytes.
func ReadVarBytes(r io.Reader) ([]byte, error) {
	rc := rc.New(r)
	ln, err := VarintReadUint64(rc)
	if err != nil {
		return nil, err
	}
	if ln > 4096 {
		return nil, fmt.Errorf("read var bytes: array too large: %d > 4096", ln)
	}
	buf := make([]byte, ln)
	_, err = io.ReadFull(rc, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadVec32 reads a varint-prefixed array of [Value256] from r.
// The maximum count is 128 elements.
func ReadVec32(r io.Reader) ([]Value256, error) {
	rc := rc.New(r)
	ln, err := VarintReadUint64(rc)
	if err != nil {
		return nil, err
	}
	if ln > 128 {
		return nil, fmt.Errorf("read vec32 too large: %d > 128", ln)
	}
	res := make([]Value256, ln)
	for n := range res {
		err = rc.ReadFull(res[n][:])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}
