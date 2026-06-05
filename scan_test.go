package zanolib_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/KarpelesLab/zanolib"
)

// TestScanTxSelfConsistency signs a transaction and then scans the resulting
// transaction with the same wallet. Every prepared destination that is
// addressed to the wallet must be detected by ScanTx with the exact amount, and
// destinations addressed elsewhere must not be detected. This exercises the full
// receive path (stealth match, amount decrypt, commitment + concealing checks)
// against the send path.
//
// Uses the committed testdata/zano_tx_signed3.bin fixture.
func TestScanTxSelfConsistency(t *testing.T) {
	wallet, err := zanolib.LoadSpendSecret(must(hex.DecodeString("d3604ff3032bbd10c072f8a768e9c2bdab9ef94fb2ed51b81b379289afa09209")), 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/zano_tx_signed3.bin")
	if err != nil {
		t.Skipf("missing fixture: %s", err)
	}
	fin, err := wallet.ParseFinalized(data)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := wallet.Sign(&fakeRnd{}, fin.FTP, fin.OneTimeKey.Scalar)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	res, err := wallet.ScanTx(signed.Tx)
	if err != nil {
		t.Fatalf("scan: %s", err)
	}

	// Multiset of amounts for destinations addressed to this wallet.
	ownAmounts := map[uint64]int{}
	for _, dst := range fin.FTP.PreparedDestinations {
		if len(dst.Addr) > 0 &&
			bytes.Equal(dst.Addr[0].SpendKey[:], wallet.SpendPubKey.Bytes()) &&
			bytes.Equal(dst.Addr[0].ViewKey[:], wallet.ViewPubKey.Bytes()) {
			ownAmounts[dst.Amount]++
		}
	}
	ownDestCount := 0
	for _, n := range ownAmounts {
		ownDestCount += n
	}

	if len(res.Outputs) != ownDestCount {
		t.Errorf("detected %d outputs, expected %d own destinations", len(res.Outputs), ownDestCount)
	}

	for _, out := range res.Outputs {
		if ownAmounts[out.Amount] == 0 {
			t.Errorf("output %d: decoded amount %d is not an own-destination amount", out.OutputIndex, out.Amount)
		} else {
			ownAmounts[out.Amount]--
		}
		if !out.IsNative {
			t.Errorf("output %d: expected native asset", out.OutputIndex)
		}
		t.Logf("detected output #%d amount=%d native=%v", out.OutputIndex, out.Amount, out.IsNative)
	}
}
