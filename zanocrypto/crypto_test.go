package zanocrypto_test

import (
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

func TestRandomScalarFullEntropy(t *testing.T) {
	// Generate multiple random scalars and verify they are distinct
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		sc := zanocrypto.RandomScalar(rand.Reader)
		key := string(sc.Bytes())
		if seen[key] {
			t.Fatal("RandomScalar produced duplicate value")
		}
		seen[key] = true
	}
}

func TestRandomScalarNonZero(t *testing.T) {
	for i := 0; i < 100; i++ {
		sc := zanocrypto.RandomScalar(rand.Reader)
		if sc.Equal(zanocrypto.ScZero) == 1 {
			t.Fatal("RandomScalar produced zero scalar")
		}
	}
}

func TestDerivationHint(t *testing.T) {
	// Generate a key derivation and verify hint is deterministic
	priv := zanocrypto.GenerateKeyScalar()
	pub := zanocrypto.PubFromPriv(priv)

	derivation, err := zanocrypto.GenerateKeyDerivation(pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	hint1 := zanocrypto.DerivationHint(derivation)
	hint2 := zanocrypto.DerivationHint(derivation)
	if hint1 != hint2 {
		t.Error("DerivationHint not deterministic")
	}
}

func TestPedersenCommitment(t *testing.T) {
	value := zanocrypto.ScalarInt(42)
	mask := zanocrypto.ScalarInt(7)

	c1 := zanocrypto.TraitZCout.CalcPedersenCommitment(value, mask)
	c2 := zanocrypto.TraitZCout.CalcPedersenCommitment(value, mask)
	if c1.Equal(c2) != 1 {
		t.Error("CalcPedersenCommitment not deterministic")
	}

	// Different mask → different commitment
	mask2 := zanocrypto.ScalarInt(8)
	c3 := zanocrypto.TraitZCout.CalcPedersenCommitment(value, mask2)
	if c1.Equal(c3) == 1 {
		t.Error("different masks should produce different commitments")
	}
}

func TestTraitInitialTranscript(t *testing.T) {
	e1 := zanocrypto.TraitInitialTranscript()
	e2 := zanocrypto.TraitInitialTranscript()
	if e1.Equal(e2) != 1 {
		t.Error("TraitInitialTranscript not deterministic")
	}
	if e1.Equal(zanocrypto.ScZero) == 1 {
		t.Error("initial transcript should not be zero")
	}
}

func TestTraitGetGenerator(t *testing.T) {
	// G and H generators at same index should differ
	g0 := zanocrypto.TraitGetGenerator(false, 0)
	h0 := zanocrypto.TraitGetGenerator(true, 0)
	if g0.Equal(h0) == 1 {
		t.Error("G and H generators at index 0 should differ")
	}

	// Same generator should be deterministic
	g0b := zanocrypto.TraitGetGenerator(false, 0)
	if g0.Equal(g0b) != 1 {
		t.Error("TraitGetGenerator not deterministic")
	}

	// Different indices should produce different generators
	g1 := zanocrypto.TraitGetGenerator(false, 1)
	if g0.Equal(g1) == 1 {
		t.Error("generators at different indices should differ")
	}
}

func TestScalarConstants(t *testing.T) {
	// ScZero should be the additive identity
	one := zanocrypto.ScOne
	sum := new(edwards25519.Scalar).Add(one, zanocrypto.ScZero)
	if sum.Equal(one) != 1 {
		t.Error("ScZero is not the additive identity")
	}

	// ScOne + ScM1 should be zero
	sum = new(edwards25519.Scalar).Add(one, zanocrypto.ScM1)
	if sum.Equal(zanocrypto.ScZero) != 1 {
		t.Error("ScOne + ScM1 should be zero")
	}

	// Sc1div8 * 8 should be 1
	eight := zanocrypto.ScalarInt(8)
	product := new(edwards25519.Scalar).Multiply(zanocrypto.Sc1div8, eight)
	if product.Equal(one) != 1 {
		t.Error("Sc1div8 * 8 should be 1")
	}
}

func TestPreparePrefixHashForSign(t *testing.T) {
	// Currently just returns txId
	txId := make([]byte, 32)
	for i := range txId {
		txId[i] = byte(i)
	}
	result, err := zanocrypto.PreparePrefixHashForSign(nil, 0, txId)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != string(txId) {
		t.Error("PreparePrefixHashForSign should return txId")
	}
}
