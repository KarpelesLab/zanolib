package zanolib_test

import (
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/zanolib"
)

func TestBuildTransferRejectsViewOnly(t *testing.T) {
	full, err := zanolib.GenerateWallet(rand.Reader, 0)
	if err != nil {
		t.Fatal(err)
	}
	vw, err := full.ExportView(0).LoadViewWallet()
	if err != nil {
		t.Fatal(err)
	}
	_, err = vw.BuildTransfer(rand.Reader, []*zanolib.TransferInput{{}}, nil, 3, 5)
	if err == nil {
		t.Error("expected BuildTransfer to reject a view-only wallet")
	}
}

func TestBuildTransferRejectsEmptyInputs(t *testing.T) {
	w, _ := zanolib.GenerateWallet(rand.Reader, 0)
	if _, err := w.BuildTransfer(rand.Reader, nil, nil, 3, 5); err == nil {
		t.Error("expected error for no inputs")
	}
}
