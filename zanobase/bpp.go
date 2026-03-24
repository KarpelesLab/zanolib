package zanobase

// BPPSignature is a Bulletproof+ signature used for aggregated range proofs,
// proving that committed values are in the range [0, 2^n).
type BPPSignature struct {
	Lv    []*Point // std::vector<public_key> size = ceil( log_2(m * n) )
	Rv    []*Point // std::vector<public_key>
	A0    *Point   // public_key
	A     *Point   // public_key
	B     *Point   // public_key
	R     *Scalar  // scalar_t
	S     *Scalar  // scalar_t
	Delta *Scalar  // scalar_t
}
