package zanompc_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/zanolib/zanocrypto"
	"github.com/KarpelesLab/zanolib/zanompc"
)

// TestThresholdCLSAGOverBroker runs the threshold CLSAG signing protocol across
// parties using tss-lib's MessageBroker transport (the same hub used by the
// frosttss tests). Every party independently assembles the identical, valid
// signature — proving the signer plugs into the existing tss-lib transport.
func TestThresholdCLSAGOverBroker(t *testing.T) {
	const n, threshold = 3, 1
	keys := runDKG(t, n, threshold)
	// Signing party IDs must carry the keygen ShareIDs as their Key, so the key
	// reindexing (SubsetForParties) and Lagrange basis line up.
	unsorted := make(tss.UnSortedPartyIDs, n)
	for i := range keys {
		unsorted[i] = tss.NewPartyID(fmt.Sprintf("p%d", i), "", keys[i].ShareID)
	}
	pIDs := tss.SortPartyIDs(unsorted)

	spendPub, err := zanompc.SpendPublicKey(keys[0].GroupPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Shared public signing context (identical for every party).
	const ringSize = 8
	const secretIndex = 4
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
	ring[secretIndex].StealthAddress = new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(hi), spendPub)
	acFull := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(s1), pAC)
	ring[secretIndex].AmountCommitment = new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, acFull)
	baidFull := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(s2, zanocrypto.C_point_X), pBAID)
	ring[secretIndex].BlindedAssetID = new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, baidFull)

	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(3*i + 5)
	}
	mkCtx := func() *zanompc.ClsagContext {
		return &zanompc.ClsagContext{
			Message: msg, Ring: ring,
			PseudoOutAmountCommitment: pAC, PseudoOutBlindedAssetID: pBAID,
			Secret1F: s1, Secret2T: s2, Hi: hi, SpendPub: spendPub, SecretIndex: secretIndex,
		}
	}

	// Wire each party to the shared hub broker (the tss transport interface).
	hub := newTestHub(n)
	peerCtx := tss.NewPeerContext(pIDs)
	signers := make([]*zanompc.ClsagSigning, n)
	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.Edwards(), peerCtx, pIDs[i], n, threshold)
		params.SetBroker(hub.brokers[i])
		sgn, err := zanompc.NewClsagSigning(context.Background(), params, keys[i], mkCtx())
		if err != nil {
			t.Fatalf("party %d NewClsagSigning: %v", i, err)
		}
		signers[i] = sgn
	}

	var firstSig, firstKI []byte
	for i := 0; i < n; i++ {
		select {
		case res := <-signers[i].Done:
			ok, err := zanocrypto.VerifyCLSAG_GGX(msg, ring, res.KeyImage, pAC, pBAID, res.Sig)
			if err != nil || !ok {
				t.Fatalf("party %d signature failed to verify: ok=%v err=%v", i, ok, err)
			}
			ki := res.KeyImage.Bytes()
			sigC := res.Sig.C.Bytes()
			if i == 0 {
				firstKI, firstSig = ki, sigC
				t.Logf("threshold CLSAG over broker verified; key image %x", ki[:8])
			} else {
				if string(ki) != string(firstKI) {
					t.Fatalf("party %d key image differs", i)
				}
				if string(sigC) != string(firstSig) {
					t.Fatalf("party %d signature differs", i)
				}
			}
		case err := <-signers[i].Err:
			t.Fatalf("party %d signing error: %v", i, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("party %d signing timed out", i)
		}
	}
}
