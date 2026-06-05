package zanompc_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/zanolib"
	"github.com/KarpelesLab/zanolib/zanompc"
)

// --- local in-process peer transport (mirrors tss-lib's frosttss test hub) ---

type hubBroker struct {
	idx      int
	hub      *testHub
	mu       sync.Mutex
	handlers map[string]tss.MessageReceiver
	pending  map[string][]*tss.JsonMessage
}

type testHub struct{ brokers []*hubBroker }

func newTestHub(n int) *testHub {
	h := &testHub{brokers: make([]*hubBroker, n)}
	for i := 0; i < n; i++ {
		h.brokers[i] = &hubBroker{
			idx:      i,
			hub:      h,
			handlers: map[string]tss.MessageReceiver{},
			pending:  map[string][]*tss.JsonMessage{},
		}
	}
	return h
}

func (b *hubBroker) Connect(typ string, dest tss.MessageReceiver) {
	b.mu.Lock()
	b.handlers[typ] = dest
	queued := b.pending[typ]
	delete(b.pending, typ)
	b.mu.Unlock()
	for _, msg := range queued {
		_ = dest.Receive(msg)
	}
}

func (b *hubBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From.Index == b.idx {
		// outbound: route to recipient(s)
		if msg.To != nil {
			return b.hub.brokers[msg.To.Index].Receive(msg)
		}
		for j, br := range b.hub.brokers {
			if j == b.idx {
				continue
			}
			if err := br.Receive(msg); err != nil {
				return err
			}
		}
		return nil
	}
	// inbound: deliver or queue until a handler registers
	b.mu.Lock()
	h, ok := b.handlers[msg.Type]
	if !ok {
		b.pending[msg.Type] = append(b.pending[msg.Type], msg)
		b.mu.Unlock()
		return nil
	}
	b.mu.Unlock()
	return h.Receive(msg)
}

// runDKG runs an {t,n} FROST-ed25519 distributed key generation across n
// in-process parties and returns each party's key share.
func runDKG(t *testing.T, n, threshold int) []*frosttss.Key {
	t.Helper()
	pIDs := tss.GenerateTestPartyIDs(n)
	hub := newTestHub(n)
	ctx := tss.NewPeerContext(pIDs)

	kgs := make([]*frosttss.Keygen, n)
	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.Edwards(), ctx, pIDs[i], n, threshold)
		params.SetBroker(hub.brokers[i])
		kg, err := frosttss.NewKeygen(context.Background(), params)
		if err != nil {
			t.Fatalf("party %d NewKeygen: %v", i, err)
		}
		kgs[i] = kg
	}

	keys := make([]*frosttss.Key, n)
	for i := 0; i < n; i++ {
		select {
		case k := <-kgs[i].Done:
			keys[i] = k
		case err := <-kgs[i].Err:
			t.Fatalf("party %d keygen error: %v", i, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("party %d keygen timed out", i)
		}
	}
	return keys
}

func TestThresholdSpendKeyAndAddress(t *testing.T) {
	const n, threshold = 3, 1 // 2-of-3
	keys := runDKG(t, n, threshold)

	// The view key is independent of the (threshold) spend key; any view
	// keypair works since it only enables scanning.
	viewWallet, err := zanolib.GenerateWallet(rand.Reader, 0)
	if err != nil {
		t.Fatal(err)
	}
	viewPub := viewWallet.ViewPubKey.Bytes()

	// Every party must derive the identical spend public key and address.
	var firstAddr string
	for i, k := range keys {
		spend, err := zanompc.SpendPublicKeyBytes(k.GroupPublicKey)
		if err != nil {
			t.Fatalf("party %d spend pub: %v", i, err)
		}
		addr, err := zanompc.Address(k.GroupPublicKey, viewPub, 0)
		if err != nil {
			t.Fatalf("party %d address: %v", i, err)
		}
		s := addr.String()
		if i == 0 {
			firstAddr = s
			t.Logf("threshold wallet address: %s", s)
			t.Logf("spend pub: %x", spend[:])
		} else if s != firstAddr {
			t.Fatalf("party %d derived a different address: %s != %s", i, s, firstAddr)
		}

		// The address must round-trip through zanolib's parser.
		parsed, err := zanolib.ParseAddress(s)
		if err != nil {
			t.Fatalf("ParseAddress: %v", err)
		}
		if fmt.Sprintf("%x", parsed.SpendKey) != fmt.Sprintf("%x", spend[:]) {
			t.Fatalf("parsed spend key mismatch")
		}
	}
}
