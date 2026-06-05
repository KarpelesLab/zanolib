package zanolib

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

// GenerateWallet creates a brand new wallet with a random spend secret read from
// rnd (use crypto/rand.Reader). The view key is derived from the spend secret
// exactly as Zano does. Set flags to 1 for an auditable wallet.
//
// This is handy for receiving test deposits: generate a wallet, fund its
// Address(), then scan for the incoming output with a view-only copy.
func GenerateWallet(rnd io.Reader, flags uint8) (*Wallet, error) {
	var seed [64]byte
	if _, err := io.ReadFull(rnd, seed[:]); err != nil {
		return nil, err
	}
	// Reduce to a canonical scalar (Zano secret keys are reduced scalars).
	s, err := new(edwards25519.Scalar).SetUniformBytes(seed[:])
	if err != nil {
		return nil, err
	}
	return LoadSpendSecret(s.Bytes(), flags)
}

// LoadViewOnly builds a view-only wallet from a view secret key and a spend
// public key (the data exported by a Zano watch-only wallet). The resulting
// wallet can detect and decode incoming outputs (ScanTx) but cannot sign, since
// the spend secret is absent.
func LoadViewOnly(viewSecretKey, spendPublicKey []byte, flags uint8) (*Wallet, error) {
	if len(viewSecretKey) != 32 {
		return nil, fmt.Errorf("view secret key must be 32 bytes, got %d", len(viewSecretKey))
	}
	if len(spendPublicKey) != 32 {
		return nil, fmt.Errorf("spend public key must be 32 bytes, got %d", len(spendPublicKey))
	}
	vpriv, err := new(edwards25519.Scalar).SetCanonicalBytes(viewSecretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid view secret key: %w", err)
	}
	spub, err := new(edwards25519.Point).SetBytes(spendPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid spend public key: %w", err)
	}
	return &Wallet{
		// SpendPrivKey intentionally nil: this is a view-only wallet.
		SpendPubKey: spub,
		ViewPrivKey: vpriv,
		ViewPubKey:  zanocrypto.PubFromPriv(vpriv),
		Flags:       flags,
	}, nil
}

// IsViewOnly reports whether the wallet lacks a spend secret key (and so can
// scan for deposits but cannot sign transactions).
func (w *Wallet) IsViewOnly() bool {
	return w.SpendPrivKey == nil
}

// ViewWalletData is a JSON-marshalable description of a view-only wallet plus
// the block height from which scanning should resume. It carries exactly what
// the scanner needs: the view secret key, the spend public key, and a start
// height. Keys are lowercase hex. Either Address or SpendPublicKey must be set;
// ViewPublicKey is optional and validated against ViewSecretKey when present.
type ViewWalletData struct {
	Address        string `json:"address,omitempty"`          // standard Zano address (alternative to the explicit keys)
	SpendPublicKey string `json:"spend_public_key,omitempty"` // hex, 32 bytes
	ViewPublicKey  string `json:"view_public_key,omitempty"`  // hex, 32 bytes (optional)
	ViewSecretKey  string `json:"view_secret_key"`            // hex, 32 bytes
	Flags          uint8  `json:"flags,omitempty"`            // 1 = auditable
	StartHeight    uint64 `json:"start_height"`               // block height to resume scanning from
}

// LoadViewWallet builds a view-only [Wallet] from a [ViewWalletData]. The
// StartHeight field is metadata for the scanner and is not part of the wallet;
// read it from the same struct when calling the scanner.
func (d *ViewWalletData) LoadViewWallet() (*Wallet, error) {
	viewSec, err := hex.DecodeString(d.ViewSecretKey)
	if err != nil {
		return nil, fmt.Errorf("view_secret_key: %w", err)
	}

	var spendPub []byte
	flags := d.Flags
	switch {
	case d.SpendPublicKey != "":
		spendPub, err = hex.DecodeString(d.SpendPublicKey)
		if err != nil {
			return nil, fmt.Errorf("spend_public_key: %w", err)
		}
	case d.Address != "":
		addr, err := ParseAddress(d.Address)
		if err != nil {
			return nil, fmt.Errorf("address: %w", err)
		}
		spendPub = addr.SpendKey
		flags = addr.Flags
	default:
		return nil, errors.New("view wallet data needs either address or spend_public_key")
	}

	w, err := LoadViewOnly(viewSec, spendPub, flags)
	if err != nil {
		return nil, err
	}

	// Optional consistency checks.
	if d.ViewPublicKey != "" {
		vpub, err := hex.DecodeString(d.ViewPublicKey)
		if err != nil {
			return nil, fmt.Errorf("view_public_key: %w", err)
		}
		if hex.EncodeToString(w.ViewPubKey.Bytes()) != hex.EncodeToString(vpub) {
			return nil, errors.New("view_public_key does not match view_secret_key")
		}
	}
	if d.Address != "" {
		if got := w.Address().String(); got != d.Address {
			return nil, fmt.Errorf("address %q does not match the provided keys (derived %q)", d.Address, got)
		}
	}
	return w, nil
}

// ExportView produces the JSON-marshalable view-only description of this wallet,
// suitable for handing to a scanner. startHeight is the block height from which
// scanning should begin (e.g. the wallet's creation height or last-scanned
// height).
func (w *Wallet) ExportView(startHeight uint64) *ViewWalletData {
	return &ViewWalletData{
		Address:        w.Address().String(),
		SpendPublicKey: hex.EncodeToString(w.SpendPubKey.Bytes()),
		ViewPublicKey:  hex.EncodeToString(w.ViewPubKey.Bytes()),
		ViewSecretKey:  hex.EncodeToString(w.ViewPrivKey.Bytes()),
		Flags:          w.Flags,
		StartHeight:    startHeight,
	}
}
