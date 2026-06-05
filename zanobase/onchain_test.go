package zanobase_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/KarpelesLab/zanolib/zanobase"
)

// TestParseOnChainBlobs parses real mainnet transaction blobs captured from the
// daemon (get_tx_details .blob, base64-decoded). It is a regression for v3
// prefix parsing and for full variant-tag coverage of on-chain extra/vout types.
func TestParseOnChainBlobs(t *testing.T) {
	for _, name := range []string{"coinbase_v3", "transfer_v3"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", name+".bin"))
			if err != nil {
				t.Skipf("missing vector: %v", err)
			}
			r := bytes.NewReader(data)
			var tx zanobase.Transaction
			if err := zanobase.Deserialize(r, &tx); err != nil {
				t.Fatalf("deserialize: %v", err)
			}
			if r.Len() != 0 {
				t.Errorf("%d trailing bytes after deserialize", r.Len())
			}
			if uint64(tx.Version) != zanobase.TransactionVersionPostHF5 {
				t.Errorf("version = %d, want 3", tx.Version)
			}
			// Re-serialize and confirm we reproduce the exact on-chain bytes.
			var out bytes.Buffer
			if err := zanobase.Serialize(&out, &tx); err != nil {
				t.Fatalf("re-serialize: %v", err)
			}
			if !bytes.Equal(out.Bytes(), data) {
				t.Errorf("re-serialized blob differs from input (%d vs %d bytes)", out.Len(), len(data))
			}
			t.Logf("%s: version=%d hardfork=%d vin=%d vout=%d extra=%d sigs=%d proofs=%d",
				name, tx.Version, tx.HardforkId, len(tx.Vin), len(tx.Vout), len(tx.Extra), len(tx.Signatures), len(tx.Proofs))
		})
	}
}
