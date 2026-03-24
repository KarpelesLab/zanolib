package zanobase

// ZCAssetSurjectionProof proves that each output's asset type matches one
// of the input asset types, without revealing which one.
type ZCAssetSurjectionProof struct {
	// zc_asset_surjection_proof
	BGEProofs []*BGEProof // std::vector<crypto::BGE_proof_s> bge_proofs
}
