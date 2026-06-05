// Package zanompc puts a Zano wallet's spend key under multi-party threshold
// control using tss-lib's FROST-ed25519 protocol. The spend secret is generated
// and held as {t,n} shares across machines and never reconstructed; spending is
// done with a threshold protocol (see sign.go).
//
// The view key is independent of the spend key here: Zano's usual
// view = keccak(spend_secret) derivation cannot run under MPC, but the view key
// only enables scanning (never spending), so it is supplied separately (e.g. a
// coordinator-held key). A Zano address is just (spend_pub, view_pub), so this
// is valid on-chain — at the cost of the usual seed-phrase recovery.
package zanompc

import (
	"fmt"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/zanolib"
	"github.com/KarpelesLab/zanolib/zanobase"
)

// SpendPublicKeyBytes converts a FROST group public key (the threshold spend
// public key) into the 32-byte Zano spend public key encoding. FROST encodes
// points in canonical RFC 8032 form, identical to Zano's ed25519 point encoding.
func SpendPublicKeyBytes(groupPub *crypto.ECPoint) (zanobase.Value256, error) {
	var out zanobase.Value256
	if groupPub == nil {
		return out, fmt.Errorf("nil group public key")
	}
	enc := frost.EncodeElement(groupPub)
	if len(enc) != 32 {
		return out, fmt.Errorf("unexpected encoded length %d", len(enc))
	}
	// Validate it decodes as a canonical ed25519 point (same library zanolib uses).
	if _, err := new(edwards25519.Point).SetBytes(enc); err != nil {
		return out, fmt.Errorf("group public key is not a valid ed25519 point: %w", err)
	}
	copy(out[:], enc)
	return out, nil
}

// SpendPublicKey returns the threshold spend public key as an edwards25519.Point
// (the curve type used throughout zanolib).
func SpendPublicKey(groupPub *crypto.ECPoint) (*edwards25519.Point, error) {
	b, err := SpendPublicKeyBytes(groupPub)
	if err != nil {
		return nil, err
	}
	return new(edwards25519.Point).SetBytes(b[:])
}

// Address builds the Zano address for a threshold wallet from its FROST group
// (spend) public key and a separately-managed view public key. flags is 0 for a
// standard wallet or 1 for auditable.
func Address(groupPub *crypto.ECPoint, viewPub []byte, flags uint8) (*zanolib.Address, error) {
	spend, err := SpendPublicKeyBytes(groupPub)
	if err != nil {
		return nil, err
	}
	if len(viewPub) != 32 {
		return nil, fmt.Errorf("view public key must be 32 bytes, got %d", len(viewPub))
	}
	typ := zanolib.PublicAddress
	if flags&1 == 1 {
		typ = zanolib.PublicAuditAddress
	}
	return &zanolib.Address{
		Type:     typ,
		Flags:    flags,
		SpendKey: append([]byte(nil), spend[:]...),
		ViewKey:  append([]byte(nil), viewPub...),
	}, nil
}
