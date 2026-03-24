package zanobase_test

import (
	"testing"

	"github.com/KarpelesLab/zanolib/zanobase"
)

func TestVarint(t *testing.T) {
	vectors := []uint64{0, 42, 1337, 0x123456789, 0xabcdef123456789}

	for _, vec := range vectors {
		buf := zanobase.VarintAppendUint64(nil, vec)
		buf2, dec, err := zanobase.VarintTakeUint64(buf)

		if err != nil {
			t.Errorf("while decoding %x: %s", vec, err)
			continue
		}
		if dec != vec {
			t.Errorf("while decoding %x: got %x instead", vec, dec)
		}
		if len(buf2) != 0 {
			t.Errorf("while decoding %x: extra buffer data: %x", vec, buf2)
		}
	}
}
