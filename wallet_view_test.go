package zanolib_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/KarpelesLab/zanolib"
)

func TestGenerateAndExportRoundTrip(t *testing.T) {
	w, err := zanolib.GenerateWallet(rand.Reader, 0)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if w.IsViewOnly() {
		t.Fatal("freshly generated wallet must not be view-only")
	}
	addr := w.Address().String()

	// Export -> JSON -> back -> view-only wallet.
	data := w.ExportView(12345)
	blob, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	var data2 zanolib.ViewWalletData
	if err := json.Unmarshal(blob, &data2); err != nil {
		t.Fatal(err)
	}
	if data2.StartHeight != 12345 {
		t.Errorf("start_height not preserved: %d", data2.StartHeight)
	}

	vw, err := data2.LoadViewWallet()
	if err != nil {
		t.Fatalf("load view wallet: %v", err)
	}
	if !vw.IsViewOnly() {
		t.Error("loaded wallet should be view-only")
	}
	if vw.Address().String() != addr {
		t.Errorf("address mismatch: %s != %s", vw.Address().String(), addr)
	}
	if !bytes.Equal(vw.SpendPubKey.Bytes(), w.SpendPubKey.Bytes()) {
		t.Error("spend public key mismatch")
	}
	if !bytes.Equal(vw.ViewPrivKey.Bytes(), w.ViewPrivKey.Bytes()) {
		t.Error("view secret key mismatch")
	}
	if !bytes.Equal(vw.ViewPubKey.Bytes(), w.ViewPubKey.Bytes()) {
		t.Error("view public key mismatch")
	}

	// A view-only wallet must refuse to sign.
	if _, err := vw.Sign(&fakeRnd{}, &zanolib.FinalizeTxParam{}, nil); err == nil {
		t.Error("expected Sign to fail on view-only wallet")
	}
}

func TestLoadViewWalletFromAddress(t *testing.T) {
	w, err := zanolib.GenerateWallet(rand.Reader, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Build view data using only the address + view secret (no explicit spend pub).
	data := &zanolib.ViewWalletData{
		Address:       w.Address().String(),
		ViewSecretKey: hex.EncodeToString(w.ViewPrivKey.Bytes()),
		StartHeight:   100,
	}
	vw, err := data.LoadViewWallet()
	if err != nil {
		t.Fatalf("load from address: %v", err)
	}
	if vw.Address().String() != w.Address().String() {
		t.Error("address-derived wallet mismatch")
	}

	// A mismatched view secret must be rejected against the address.
	other, _ := zanolib.GenerateWallet(rand.Reader, 0)
	bad := &zanolib.ViewWalletData{
		Address:       w.Address().String(),
		ViewSecretKey: hex.EncodeToString(other.ViewPrivKey.Bytes()),
		ViewPublicKey: hex.EncodeToString(w.ViewPubKey.Bytes()), // belongs to w, not other
	}
	if _, err := bad.LoadViewWallet(); err == nil {
		t.Error("expected mismatch error for wrong view public key")
	}
}

// TestViewOnlyScanMatchesFull confirms a view-only wallet detects exactly the
// same outputs as the full wallet. Requires the local fixture; skips otherwise.
func TestViewOnlyScanMatchesFull(t *testing.T) {
	full, err := zanolib.LoadSpendSecret(must(hex.DecodeString("d3604ff3032bbd10c072f8a768e9c2bdab9ef94fb2ed51b81b379289afa09209")), 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/zano_tx_signed3.bin")
	if err != nil {
		t.Skipf("missing fixture: %s", err)
	}
	fin, err := full.ParseFinalized(data)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := full.Sign(&fakeRnd{}, fin.FTP, fin.OneTimeKey.Scalar)
	if err != nil {
		t.Fatal(err)
	}

	view, err := full.ExportView(0).LoadViewWallet()
	if err != nil {
		t.Fatal(err)
	}

	resFull, err := full.ScanTx(signed.Tx)
	if err != nil {
		t.Fatal(err)
	}
	resView, err := view.ScanTx(signed.Tx)
	if err != nil {
		t.Fatal(err)
	}
	if len(resFull.Outputs) != len(resView.Outputs) || len(resView.Outputs) == 0 {
		t.Fatalf("output count mismatch: full=%d view=%d", len(resFull.Outputs), len(resView.Outputs))
	}
	for i := range resFull.Outputs {
		if resFull.Outputs[i].Amount != resView.Outputs[i].Amount {
			t.Errorf("output %d amount mismatch: full=%d view=%d", i, resFull.Outputs[i].Amount, resView.Outputs[i].Amount)
		}
	}
	t.Logf("view-only wallet detected %d outputs identical to the full wallet", len(resView.Outputs))
}
