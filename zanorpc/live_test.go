package zanorpc_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/KarpelesLab/zanolib"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanorpc"
)

// liveEndpoint is used by the opt-in live tests. Set ZANO_RPC_LIVE=1 to run them
// (they make real network calls to a public Zano daemon).
const liveEndpoint = "https://rpc.modchain.net/chain/zano/rpc"

func liveOrSkip(t *testing.T) {
	if os.Getenv("ZANO_RPC_LIVE") == "" {
		t.Skip("set ZANO_RPC_LIVE=1 to run live RPC tests")
	}
}

// TestLiveParseScan fetches a range of real blocks and confirms every
// transaction parses for scanning and scans without error. This is the
// integration regression for on-chain variant-tag coverage.
func TestLiveParseScan(t *testing.T) {
	liveOrSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	c := zanorpc.New(liveEndpoint)
	h, err := c.GetBlockCount(ctx)
	if err != nil {
		t.Fatalf("getblockcount: %v", err)
	}
	t.Logf("chain height = %d", h)

	// a throwaway wallet: we don't expect to own anything, we just exercise the
	// full fetch -> parse -> scan pipeline against real data.
	w, err := zanolib.LoadSpendSecret(mustHex(t, "d3604ff3032bbd10c072f8a768e9c2bdab9ef94fb2ed51b81b379289afa09209"), 0)
	if err != nil {
		t.Fatal(err)
	}

	blocks, err := c.GetBlocksDetails(ctx, 3712000, 12, false)
	if err != nil {
		t.Fatalf("get_blocks_details: %v", err)
	}
	n := 0
	for _, blk := range blocks {
		for _, txb := range blk.Transactions {
			td, err := c.GetTxDetails(ctx, txb.Id)
			if err != nil {
				t.Fatalf("get_tx_details %s: %v", txb.Id, err)
			}
			tx, err := zanobase.DeserializeForScan(bytes.NewReader(td.Blob))
			if err != nil {
				t.Fatalf("parse %s (%d bytes): %v", txb.Id, len(td.Blob), err)
			}
			if _, err := w.ScanTx(tx); err != nil {
				t.Errorf("scan %s: %v", txb.Id, err)
			}
			n++
		}
	}
	t.Logf("parsed+scanned %d transactions across %d blocks", n, len(blocks))
}

// TestLiveScanRange exercises the Scanner driver over a small confirmed range.
func TestLiveScanRange(t *testing.T) {
	liveOrSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	w, err := zanolib.LoadSpendSecret(mustHex(t, "d3604ff3032bbd10c072f8a768e9c2bdab9ef94fb2ed51b81b379289afa09209"), 0)
	if err != nil {
		t.Fatal(err)
	}
	s := zanorpc.NewScanner(w, liveEndpoint)
	s.BatchSize = 5

	from, to := uint64(3713900), uint64(3713912)
	last, err := s.ScanRange(ctx, from, to, func(d zanorpc.Deposit) error {
		t.Logf("deposit h=%d tx=%s amount=%d global_index=%d native=%v",
			d.Height, d.TxId, d.Out.Amount, d.GlobalIndex, d.Out.IsNative)
		return nil
	})
	if err != nil {
		t.Fatalf("scanrange: %v", err)
	}
	if last != to {
		t.Errorf("last scanned height = %d, want %d", last, to)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
