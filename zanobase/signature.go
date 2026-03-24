package zanobase

// ZCSig represents a zero-confidential signature containing pseudo-output
// commitments and a CLSAG-GGX ring signature.
type ZCSig struct {
	// ZC_sig
	PseudoOutAmountCommitment *Point // premultiplied by 1/8
	PseudoOutBlindedAssetId   *Point // premultiplied by 1/8
	// crypto::CLSAG_GGX_signature_serialized clsags_ggx
	GGX *CLSAG_Sig
}

// CLSAG_Sig is a Confidential Linkable Spontaneous Anonymous Group signature
// with three layers (GGX variant): stealth address, amount, and asset ID.
type CLSAG_Sig struct {
	C  *Scalar   // scalar_t
	Rg []*Scalar // for G-components (layers 0, 1),    size = size of the ring
	Rx []*Scalar // for X-component  (layer 2),        size = size of the ring
	K1 *Point    // public_key auxiliary key image for layer 1 (G)
	K2 *Point    // public_key auxiliary key image for layer 2 (X)
}

// CLSAG_GGX_Input holds the serialized ring member data for a CLSAG-GGX signature.
type CLSAG_GGX_Input struct {
	BlindedAssetId   Value256
	StealthAddress   Value256
	AmountCommitment Value256
}
