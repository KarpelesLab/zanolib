package zanobase

// TxInGen represents a coinbase (generation) transaction input.
type TxInGen struct {
	Height uint64
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
