package zanocrypto

import "github.com/KarpelesLab/zanolib/zanobase"

func PreparePrefixHashForSign(tx *zanobase.Transaction, inIndex int, txId []byte) ([]byte, error) {
	// TODO get_tx_flags(tx) & TX_FLAG_SIGNATURE_MODE_SEPARATE
	return txId, nil
}
