package zanompc_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/zanolib/zanocrypto"
	"github.com/KarpelesLab/zanolib/zanompc"
)

// TestDeriveViewSecret checks that every committee member derives the same view
// secret over the broker, that it is deterministic (a fresh committee from the
// same shares reproduces it), and that it equals the reference value
// HashToScalar(domain || x*ViewKeyBase(spendPub)) where x is the reconstructed
// spend secret.
func TestDeriveViewSecret(t *testing.T) {
	const n, threshold = 3, 1
	keys := runDKG(t, n, threshold)

	unsorted := make(tss.UnSortedPartyIDs, n)
	for i := range keys {
		unsorted[i] = tss.NewPartyID(fmt.Sprintf("p%d", i), "", keys[i].ShareID)
	}
	pIDs := tss.SortPartyIDs(unsorted)

	spendPub, err := zanompc.SpendPublicKey(keys[0].GroupPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Reference: V = x*P, view_secret = HashToScalar("..._SECRET\0" || V).
	x := reconstructSecret(t, keys)
	V := new(edwards25519.Point).ScalarMult(x, zanompc.ViewKeyBase(spendPub))
	want := zanocrypto.HashToScalar(append([]byte("ZANO_THRESHOLD_VIEWKEY_SECRET\x00"), V.Bytes()...))

	derive := func() []*edwards25519.Scalar {
		hub := newTestHub(n)
		peerCtx := tss.NewPeerContext(pIDs)
		out := make([]*edwards25519.Scalar, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				params := tss.NewParameters(tss.Edwards(), peerCtx, pIDs[i], n, threshold)
				params.SetBroker(hub.brokers[i])
				signer, err := zanompc.NewThresholdInputSigner(context.Background(), params, keys[i])
				if err != nil {
					errs[i] = err
					return
				}
				out[i], errs[i] = signer.DeriveViewSecret()
			}(i)
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("party %d: %v", i, err)
			}
		}
		return out
	}

	first := derive()
	for i, vs := range first {
		if vs.Equal(want) != 1 {
			t.Fatalf("party %d: view secret %x != reference %x", i, vs.Bytes(), want.Bytes())
		}
	}

	// Determinism: a second independent run over the same shares reproduces it.
	for i, vs := range derive() {
		if vs.Equal(first[i]) != 1 {
			t.Fatalf("party %d: view secret not reproducible across runs", i)
		}
	}

	t.Logf("threshold view secret %x derived identically by %d parties, reproducible", want.Bytes()[:8], n)
}
