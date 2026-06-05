package zanompc_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/zanolib"
	"github.com/KarpelesLab/zanolib/zanocrypto"
	"github.com/KarpelesLab/zanolib/zanompc"
)

// ThresholdInputSigner must satisfy the interface Wallet.SignWith consumes.
var _ zanolib.InputSigner = (*zanompc.ThresholdInputSigner)(nil)

// TestThresholdInputSigner drives the MPC signer through the zanolib.InputSigner
// interface (KeyImage then SignCLSAG) concurrently across a committee over
// tss-lib's broker, exactly as Wallet.SignWith would. It checks that the key
// image matches a local signer holding the reconstructed secret, and that the
// CLSAG signature verifies.
func TestThresholdInputSigner(t *testing.T) {
	const n, threshold = 3, 1
	keys := runDKG(t, n, threshold)

	// Signing party IDs carry the keygen ShareIDs as their Key.
	unsorted := make(tss.UnSortedPartyIDs, n)
	for i := range keys {
		unsorted[i] = tss.NewPartyID(fmt.Sprintf("p%d", i), "", keys[i].ShareID)
	}
	pIDs := tss.SortPartyIDs(unsorted)

	spendPub, err := zanompc.SpendPublicKey(keys[0].GroupPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Synthetic single-input context: real stealth = hi*G + spendPub.
	const ringSize = 8
	const secretIndex = 2
	hi := zanocrypto.RandomScalar(rand.Reader)
	s1 := zanocrypto.RandomScalar(rand.Reader)
	s2 := zanocrypto.RandomScalar(rand.Reader)
	pAC := new(edwards25519.Point).ScalarBaseMult(zanocrypto.RandomScalar(rand.Reader))
	pBAID := new(edwards25519.Point).ScalarBaseMult(zanocrypto.RandomScalar(rand.Reader))
	ring := make([]zanocrypto.CLSAG_GGXInputRef, ringSize)
	for i := range ring {
		ring[i] = zanocrypto.CLSAG_GGXInputRef{
			StealthAddress:   new(edwards25519.Point).ScalarBaseMult(zanocrypto.RandomScalar(rand.Reader)),
			AmountCommitment: new(edwards25519.Point).ScalarBaseMult(zanocrypto.RandomScalar(rand.Reader)),
			BlindedAssetID:   new(edwards25519.Point).ScalarBaseMult(zanocrypto.RandomScalar(rand.Reader)),
		}
	}
	inEPub := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(hi), spendPub)
	ring[secretIndex].StealthAddress = inEPub
	acFull := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(s1), pAC)
	ring[secretIndex].AmountCommitment = new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, acFull)
	baidFull := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(s2, zanocrypto.C_point_X), pBAID)
	ring[secretIndex].BlindedAssetID = new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, baidFull)

	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(11*i + 2)
	}

	// Reference key image from a local signer holding the reconstructed secret.
	x := reconstructSecret(t, keys)
	wantKI, err := zanolib.LocalInputSigner(x).KeyImage(hi, inEPub)
	if err != nil {
		t.Fatal(err)
	}

	// Run all parties concurrently over the broker, each through the interface.
	hub := newTestHub(n)
	peerCtx := tss.NewPeerContext(pIDs)
	results := make([]struct {
		ki  *edwards25519.Point
		ok  bool
		err error
	}, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			params := tss.NewParameters(tss.Edwards(), peerCtx, pIDs[i], n, threshold)
			params.SetBroker(hub.brokers[i])
			signer, err := zanompc.NewThresholdInputSigner(context.Background(), params, keys[i])
			if err != nil {
				results[i].err = err
				return
			}
			var sgn zanolib.InputSigner = signer
			ki, err := sgn.KeyImage(hi, inEPub)
			if err != nil {
				results[i].err = err
				return
			}
			sig, err := sgn.SignCLSAG(rand.Reader, hi, msg, ring, ki, pAC, pBAID, s1, s2, secretIndex)
			if err != nil {
				results[i].err = err
				return
			}
			ok, err := zanocrypto.VerifyCLSAG_GGX(msg, ring, ki, pAC, pBAID, sig)
			results[i].ki, results[i].ok, results[i].err = ki, ok, err
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if results[i].err != nil {
			t.Fatalf("party %d: %v", i, results[i].err)
		}
		if !results[i].ok {
			t.Fatalf("party %d: signature did not verify", i)
		}
		if results[i].ki.Equal(wantKI) != 1 {
			t.Fatalf("party %d: key image != local signer key image", i)
		}
	}
	t.Logf("MPC InputSigner: %d parties signed concurrently; key image %x matches local signer; CLSAG verifies", n, wantKI.Bytes()[:8])
}
