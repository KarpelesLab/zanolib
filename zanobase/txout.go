package zanobase

// TxOutZarcanium represents a Zarcanum-type transaction output with stealth
// address, concealing point, Pedersen commitment, and blinded asset ID.
type TxOutZarcanium struct {
	// tx_out_zarcanum
	StealthAddress   Value256
	ConcealingPoint  Value256 // group element Q, see also Zarcanum paper, premultiplied by 1/8
	AmountCommitment Value256 // premultiplied by 1/8
	BlindedAssetId   Value256 // group element T, premultiplied by 1/8
	EncryptedAmount  uint64
	MixAttr          uint8
}
