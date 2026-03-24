package zanocrypto

import "github.com/KarpelesLab/zanolib/zanobase"

// PreparePrefixHashForSign returns the hash to be signed for the given input.
// Currently returns the transaction ID directly; separate signature mode
// support is not yet implemented.
func PreparePrefixHashForSign(tx *zanobase.Transaction, inIndex int, txId []byte) ([]byte, error) {
	// TODO get_tx_flags(tx) & TX_FLAG_SIGNATURE_MODE_SEPARATE
	return txId, nil
}
