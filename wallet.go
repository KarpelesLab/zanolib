package zanolib

import (
	"bytes"
	"slices"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
	"golang.org/x/crypto/sha3"
)

type Wallet struct {
	SpendPrivKey *edwards25519.Scalar
	SpendPubKey  *edwards25519.Point
	ViewPrivKey  *edwards25519.Scalar
	ViewPubKey   *edwards25519.Point
	Flags        uint8 // flag 1 = auditable
}

// LoadSpendSecret initializesd a Wallet based on a spend secret as found in
// zano if you run spendkey. It will automatically derive the view key using
// the appropriate method for Zano.
//
// Set flags to zero for normal keys, or 1 for auditable keys.
func LoadSpendSecret(pk []byte, flags uint8) (*Wallet, error) {
	pk = slices.Clone(pk)
	viewKey := hsum(sha3.NewLegacyKeccak256, pk)

	priv, err := new(edwards25519.Scalar).SetCanonicalBytes(pk)
	if err != nil {
		return nil, err
	}
	//vpriv, err := new(edwards25519.Scalar).SetBytesWithClamping(viewKey)
	// zano does *not* clamp view keys. Clamping keys here would cause a different key to be
	// created and overall things not to work.
	var viewKey64 [64]byte
	copy(viewKey64[:], viewKey)
	vpriv, err := new(edwards25519.Scalar).SetUniformBytes(viewKey64[:])
	if err != nil {
		return nil, err
	}

	res := &Wallet{
		SpendPrivKey: priv,
		SpendPubKey:  zanocrypto.PubFromPriv(priv),
		ViewPrivKey:  vpriv,
		ViewPubKey:   zanocrypto.PubFromPriv(vpriv),
		Flags:        flags,
	}
	//log.Printf("spend pub = %x", res.SpendPubKey.Bytes())
	//log.Printf("view priv = %x", res.ViewPrivKey.Bytes())
	//log.Printf("view pub = %x", res.ViewPubKey.Bytes())
	//log.Printf("addr = %s", res.Address())

	return res, nil
}

// Address returns this wallet's address.
func (w *Wallet) Address() *Address {
	typ := PublicAddress
	if w.Flags&1 == 1 {
		typ = PublicAuditAddress
	}

	addr := &Address{
		Type:     typ,
		Flags:    w.Flags,
		SpendKey: w.SpendPubKey.Bytes(),
		ViewKey:  w.ViewPubKey.Bytes(),
	}

	return addr
}

func (w *Wallet) ParseFTP(buf []byte) (*FinalizeTxParam, error) {
	// buf is encrypted using chacha8 xor initialized with the view private key
	key := w.ViewPrivKey.Bytes()
	return ParseFTP(buf, key)
}

func (w *Wallet) ParseFinalized(buf []byte) (*FinalizedTx, error) {
	// buf is encrypted using chacha8 xor initialized with the view private key
	key := w.ViewPrivKey.Bytes()
	return ParseFinalized(buf, key)
}

// Encrypt will serialize and encrypt whatever data is passed (can be a FTP or a finalized transaction)
// so it can be read again.
func (w *Wallet) Encrypt(data any) ([]byte, error) {
	out := &bytes.Buffer{}
	err := zanobase.Serialize(out, data)
	if err != nil {
		return nil, err
	}
	code, err := zanocrypto.ChaCha8GenerateKey(w.ViewPrivKey.Bytes())
	if err != nil {
		return nil, err
	}
	buf, err := zanocrypto.ChaCha8(code, make([]byte, 8), out.Bytes())
	if err != nil {
		return nil, err
	}
	return buf, nil
}
