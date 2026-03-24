package zanocrypto_test

import (
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

func TestHashHelperBasic(t *testing.T) {
	hh := zanocrypto.NewHashHelper()

	// Add a 32-byte value
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	hh.AddBytes(data)

	result := hh.CalcHash()
	if result == nil {
		t.Fatal("CalcHash returned nil")
	}

	// Should produce the same result with same input
	hh2 := zanocrypto.NewHashHelper()
	hh2.AddBytes(data)
	result2 := hh2.CalcHash()
	if result.Equal(result2) != 1 {
		t.Error("HashHelper not deterministic")
	}
}

func TestHashHelperCalcHashResets(t *testing.T) {
	hh := zanocrypto.NewHashHelper()
	data := make([]byte, 32)
	hh.AddBytes(data)
	r1 := hh.CalcHash()

	// After CalcHash, state should be reset, so adding the same data again should give the same result
	hh.AddBytes(data)
	r2 := hh.CalcHash()
	if r1.Equal(r2) != 1 {
		t.Error("CalcHash didn't properly reset state")
	}
}

func TestHashHelperCalcHashKeep(t *testing.T) {
	hh := zanocrypto.NewHashHelper()
	data := make([]byte, 32)
	hh.AddBytes(data)

	r1 := hh.CalcHashKeep()
	r2 := hh.CalcHashKeep()
	if r1.Equal(r2) != 1 {
		t.Error("CalcHashKeep should return same result without reset")
	}
}

func TestHashHelperCalcRawHash(t *testing.T) {
	hh := zanocrypto.NewHashHelper()
	data := make([]byte, 32)
	hh.AddBytes(data)

	raw := hh.CalcRawHash()
	if len(raw) != 32 {
		t.Fatalf("expected 32 bytes from CalcRawHash, got %d", len(raw))
	}
}

func TestHashHelperAdd(t *testing.T) {
	hh := zanocrypto.NewHashHelper()
	g := edwards25519.NewGeneratorPoint()
	hh.Add(g)
	result := hh.CalcHash()
	if result == nil {
		t.Fatal("CalcHash returned nil after Add")
	}
}

func TestHashHelperAddBytesModL(t *testing.T) {
	hh := zanocrypto.NewHashHelper()
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	hh.AddBytesModL(data)
	result := hh.CalcHash()
	if result == nil {
		t.Fatal("CalcHash returned nil after AddBytesModL")
	}
}

func TestHashHelperAddBytesPanicsOnWrongSize(t *testing.T) {
	hh := zanocrypto.NewHashHelper()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for non-32-byte input")
		}
	}()
	hh.AddBytes([]byte{1, 2, 3})
}

func TestPubFromPriv(t *testing.T) {
	// The scalar 1 should give the generator point
	scBytes, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	sc, _ := new(edwards25519.Scalar).SetCanonicalBytes(scBytes)

	pub := zanocrypto.PubFromPriv(sc)
	g := edwards25519.NewGeneratorPoint()
	if pub.Equal(g) != 1 {
		t.Error("PubFromPriv(1) should equal generator point")
	}
}

func TestScalarInt(t *testing.T) {
	tests := []uint64{0, 1, 42, 255, 1000, 0xffffffff}
	for _, v := range tests {
		sc := zanocrypto.ScalarInt(v)
		if sc == nil {
			t.Fatalf("ScalarInt(%d) returned nil", v)
		}
		// Verify by checking that the first 8 bytes match the LE encoding
		b := sc.Bytes()
		var decoded uint64
		for i := 0; i < 8; i++ {
			decoded |= uint64(b[i]) << (8 * i)
		}
		if decoded != v {
			t.Errorf("ScalarInt(%d): decoded %d", v, decoded)
		}
	}
}

func TestRandomScalar(t *testing.T) {
	// Just test it doesn't panic and returns non-nil
	sc := zanocrypto.GenerateKeyScalar()
	if sc == nil {
		t.Fatal("GenerateKeyScalar returned nil")
	}
}
