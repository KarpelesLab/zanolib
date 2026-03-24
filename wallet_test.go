package zanolib_test

import (
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/zanolib"
)

func TestLoadSpendSecret(t *testing.T) {
	// A valid scalar (must be < L, the group order). Use a known-valid 32-byte scalar.
	spendKey, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")

	// Non-auditable wallet (flags=0)
	w, err := zanolib.LoadSpendSecret(spendKey, 0)
	if err != nil {
		t.Fatalf("LoadSpendSecret failed: %v", err)
	}

	if w.SpendPubKey == nil {
		t.Fatal("SpendPubKey is nil")
	}
	if w.ViewPubKey == nil {
		t.Fatal("ViewPubKey is nil")
	}
	if w.SpendPrivKey == nil {
		t.Fatal("SpendPrivKey is nil")
	}
	if w.ViewPrivKey == nil {
		t.Fatal("ViewPrivKey is nil")
	}
	if w.Flags != 0 {
		t.Errorf("expected flags=0, got %d", w.Flags)
	}

	// Verify the wallet address round-trips
	addr := w.Address()
	if addr == nil {
		t.Fatal("Address() returned nil")
	}
	addrStr := addr.String()
	parsed, err := zanolib.ParseAddress(addrStr)
	if err != nil {
		t.Fatalf("failed to parse generated address: %v", err)
	}
	if hex.EncodeToString(parsed.SpendKey) != hex.EncodeToString(addr.SpendKey) {
		t.Error("spend key mismatch after round-trip")
	}
	if hex.EncodeToString(parsed.ViewKey) != hex.EncodeToString(addr.ViewKey) {
		t.Error("view key mismatch after round-trip")
	}
}

func TestLoadSpendSecretAuditable(t *testing.T) {
	spendKey, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")

	w, err := zanolib.LoadSpendSecret(spendKey, 1)
	if err != nil {
		t.Fatalf("LoadSpendSecret failed: %v", err)
	}
	if w.Flags != 1 {
		t.Errorf("expected flags=1, got %d", w.Flags)
	}

	addr := w.Address()
	if addr.Type != zanolib.PublicAuditAddress {
		t.Errorf("expected PublicAuditAddress, got %v", addr.Type)
	}
}

func TestLoadSpendSecretDeterministic(t *testing.T) {
	spendKey, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")

	w1, err := zanolib.LoadSpendSecret(spendKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := zanolib.LoadSpendSecret(spendKey, 0)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(w1.SpendPubKey.Bytes()) != hex.EncodeToString(w2.SpendPubKey.Bytes()) {
		t.Error("SpendPubKey not deterministic")
	}
	if hex.EncodeToString(w1.ViewPubKey.Bytes()) != hex.EncodeToString(w2.ViewPubKey.Bytes()) {
		t.Error("ViewPubKey not deterministic")
	}
	if hex.EncodeToString(w1.ViewPrivKey.Bytes()) != hex.EncodeToString(w2.ViewPrivKey.Bytes()) {
		t.Error("ViewPrivKey not deterministic")
	}
}

func TestLoadSpendSecretDoesNotMutateInput(t *testing.T) {
	original := "0100000000000000000000000000000000000000000000000000000000000000"
	spendKey, _ := hex.DecodeString(original)
	before := hex.EncodeToString(spendKey)

	_, err := zanolib.LoadSpendSecret(spendKey, 0)
	if err != nil {
		t.Fatal(err)
	}

	after := hex.EncodeToString(spendKey)
	if before != after {
		t.Error("LoadSpendSecret mutated input slice")
	}
}

func TestLoadSpendSecretInvalidKey(t *testing.T) {
	// Too short
	_, err := zanolib.LoadSpendSecret([]byte{1, 2, 3}, 0)
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestWalletAddressKnownVector(t *testing.T) {
	// Known spend secret that produces a known address
	spendKey, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")

	w, err := zanolib.LoadSpendSecret(spendKey, 0)
	if err != nil {
		t.Fatal(err)
	}

	addr := w.Address()
	// Verify the spend pub key matches the known test vector
	spendPub := hex.EncodeToString(addr.SpendKey)
	if spendPub != hex.EncodeToString(w.SpendPubKey.Bytes()) {
		t.Error("address spend key doesn't match wallet spend pub key")
	}
	viewPub := hex.EncodeToString(addr.ViewKey)
	if viewPub != hex.EncodeToString(w.ViewPubKey.Bytes()) {
		t.Error("address view key doesn't match wallet view pub key")
	}
}
