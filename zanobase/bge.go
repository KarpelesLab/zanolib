package zanobase

// BGEProof is a Background Equivalence proof used in asset surjection proofs
// to demonstrate that an output's asset ID matches one of the input asset IDs.
type BGEProof struct {
	A  *Point    // public_key, premultiplied by 1/8
	B  *Point    // public_key, premultiplied by 1/8
	Pk []*Point  // premultiplied by 1/8, size = m
	F  []*Scalar // scalar_vec_t size = m * (n - 1)
	Y  *Scalar   // scalar_t
	Z  *Scalar   // scalar_t
}
