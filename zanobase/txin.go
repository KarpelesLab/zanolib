package zanobase

// TxInGen represents a coinbase (generation) transaction input.
// currency::txin_gen { size_t height; } // VARINT
type TxInGen struct {
	Height uint64 `epee:"varint"`
}

// TxInToKey is a legacy (pre-HF4) transparent transaction input.
//
//	currency::txin_to_key : referring_input {
//	  uint64_t amount /*VARINT*/; <key_offsets from referring_input>;
//	  crypto::key_image k_image; std::vector<txin_etc_details_v> etc_details; }
type TxInToKey struct {
	Amount     uint64     `json:"amount" epee:"varint"`
	KeyOffsets []*Variant `json:"key_offsets"` // txout_ref_v = variant<uint64_t, ref_by_id>
	KImage     *Point     `json:"k_image"`     // crypto::key_image
	EtcDetails []*Variant `json:"etc_details,omitempty"`
}

// TxInZcInput represents a zero-confidential transaction input with ring
// member key offsets and a key image for double-spend prevention.
type TxInZcInput struct {
	// referring_input
	KeyOffsets []*Payload `json:"key_offsets"` // std::vector<txout_ref_v>; typedef boost::variant<uint64_t, ref_by_id> txout_ref_v
	// txin_zc_input
	KeyImage   *Point     `json:"key_image"`             // crypto::key_image = ec_point
	EtcDetails []*Payload `json:"etc_details,omitempty"` // std::vector<txin_etc_details_v> = std::vector<boost::variant<signed_parts, extra_attachment_info>>
}
