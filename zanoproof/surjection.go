package zanoproof

import (
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

func GenerateAssetSurjectionProof(rnd io.Reader, tx *zanobase.Transaction, contextHash []byte, ogc *zanobase.GenContext) error {
	outsCount := len(ogc.BlindedAssetIds)
	if outsCount == 0 {
		return errors.New("blinded_asset_ids shouldn't be empty")
	}

	zcInsCount := len(ogc.PseudoOutsBlindedAssetIds)

	result := new(zanobase.ZCAssetSurjectionProof)

	// ins
	//ogc.pseudo_outs_blinded_asset_ids;             // T^p_i = T_real + r'_i * X
	//ogc.pseudo_outs_plus_real_out_blinding_masks;  // r_pi + r'_j
	// outs
	//ogc.blinded_asset_ids;                         // T'_j = H_j + s_j * X
	//ogc.asset_id_blinding_masks;                   // s_j

	for j := 0; j < outsCount; j += 1 {
		H := ogc.AssetIds[j].Point
		T := ogc.BlindedAssetIds[j].Point

		ring := make([]*edwards25519.Point, 0, zcInsCount)

		secret := new(edwards25519.Scalar).Negate(ogc.AssetIdBlindingMasks[j].Scalar)
		secretIndex := -1

		for i := 0; i < zcInsCount; i++ {
			ring = append(ring, new(edwards25519.Point).Subtract(ogc.PseudoOutsBlindedAssetIds[i].Point, T))
			if secretIndex == -1 && ogc.RealZcInsAssetIds[i].Equal(H) == 1 {
				secretIndex = i
				secret = new(edwards25519.Scalar).Add(secret, ogc.PseudoOutsPlusRealOutBlindingMasks[secretIndex].Scalar)
			}
		}

		// additional ring member for native coins in txs with non-zc inputs
		// TODO

		// additional ring member for asset emitting operation (which has asset operation commitment in the inputs part)
		// TODO

		if secretIndex == -1 {
			return fmt.Errorf("out #%d: cannot find a corresponding asset id in inputs or asset operations; asset id: %x", j, H.Bytes())
		}

		bge, err := zanocrypto.Generate_BGE_Proof(rnd, contextHash, ring, secret, secretIndex)
		if err != nil {
			return err
		}
		result.BGEProofs = append(result.BGEProofs, bge)
	}

	tx.Proofs = append(tx.Proofs, &zanobase.Variant{Tag: zanobase.TagZcAssetSurjectionProof, Value: result})

	return nil
}
