package zanobase

import "golang.org/x/crypto/sha3"

// TransactionPrefix contains the hashable prefix of a transaction: version,
// inputs, extra fields, and outputs.
type TransactionPrefix struct {
	Version Varint     `json:"version"` // varint, ==2
	Vin     []*Variant `json:"vin"`     // txin_v = boost::variant<txin_gen[0], txin_to_key[1], txin_multisig[2], txin_htlc[34], txin_zc_input[37]>
	Extra   []*Variant `json:"extra"`   // extra_v
	Vout    []*Variant `json:"vout"`    // tx_out_v = boost::variant<tx_out_bare[36], tx_out_zarcanum[38]>
}

// Transaction represents a complete Zano transaction including the prefix,
// attachments, signatures, and proofs.
type Transaction struct {
	Version Varint     `json:"version"` // varint, ==2
	Vin     []*Variant `json:"vin"`     // txin_v = boost::variant<txin_gen[0], txin_to_key[1], txin_multisig[2], txin_htlc[34], txin_zc_input[37]>
	Extra   []*Variant `json:"extra"`   // extra_v
	Vout    []*Variant `json:"vout"`    // tx_out_v = boost::variant<tx_out_bare[36], tx_out_zarcanum[38]>
	// up to here this was transaction_prefix
	Attachment []*Variant `json:"attachment,omitempty"`
	Signatures []*Variant `json:"signatures"` // signature_v = boost::variant<NLSAG_sig, void_sig, ZC_sig, zarcanum_sig>
	Proofs     []*Variant `json:"proofs"`     // proof_v
}

// TransactionV3 extends [Transaction] with a hardfork ID field.
type TransactionV3 struct {
	Version Varint     `json:"version"` // varint, ==2
	Vin     []*Variant `json:"vin"`     // txin_v = boost::variant<txin_gen[0], txin_to_key[1], txin_multisig[2], txin_htlc[34], txin_zc_input[37]>
	Extra   []*Variant `json:"extra"`   // extra_v
	Vout    []*Variant `json:"vout"`    // tx_out_v = boost::variant<tx_out_bare[36], tx_out_zarcanum[38]>
	// up to here this was transaction_prefix
	Attachment []*Variant `json:"attachment,omitempty"`
	Signatures []*Variant `json:"signatures"`  // signature_v = boost::variant<NLSAG_sig, void_sig, ZC_sig, zarcanum_sig>
	Proofs     []*Variant `json:"proofs"`      // proof_v
	HardforkId uint8      `json:"hardfork_id"` // uint8_t
}

// Prefix returns the hashable prefix portion of the transaction.
func (tx *Transaction) Prefix() *TransactionPrefix {
	return &TransactionPrefix{tx.Version, tx.Vin, tx.Extra, tx.Vout}
}

// Hash computes the Keccak-256 hash of the serialized transaction prefix.
func (txp *TransactionPrefix) Hash() ([]byte, error) {
	h := sha3.NewLegacyKeccak256()
	err := Serialize(h, txp)
	return h.Sum(nil), err
}

// GetFee returns the transaction fee by looking for a [ZarcaniumTxDataV1]
// in the extra fields. Returns (0, false) if no fee is found.
func (tx *Transaction) GetFee() (uint64, bool) {
	// simple get fee: tx.Extra should contain a ZarcaniumTxDataV1
	for _, e := range tx.Extra {
		if e.Tag == TagZarcaniumTxDataV1 {
			return e.Value.(*ZarcaniumTxDataV1).Fee, true
		}
	}
	return 0, false
}
