package zanolib

import (
	"bytes"
	"errors"
	"io"

	"github.com/ModChain/zanolib/zanobase"
	"github.com/ModChain/zanolib/zanocrypto"
)

type FinalizeTxParam struct {
	UnlockTime           uint64
	Extra                []*zanobase.Variant         // currency::extra_v
	Attachments          []*zanobase.Variant         // currency::attachment_v
	CryptAddress         *zanobase.AccountPublicAddr // currency::account_public_address
	TxOutsAttr           uint8
	Shuffle              bool
	Flags                uint8
	MultisigId           zanobase.Value256 // crypto::hash
	Sources              []*TxSource       // currency::tx_source_entry
	SelectedTransfers    []zanobase.Varint // not sure why, but this is encoded as "01 00" in the bytestream
	PreparedDestinations []*TxDest         // currency::tx_destination_entry
	ExpirationTime       uint64
	SpendPubKey          *zanobase.Point // only for validations
	TxVersion            uint64
	TxHardforkId         uint64
	ModeSeparateFee      uint64
	//GenContext      *GenContext // if flags & TX_FLAG_SIGNATURE_MODE_SEPARATE
}

func ParseFTP(buf, viewSecretKey []byte) (*FinalizeTxParam, error) {
	code, err := zanocrypto.ChaCha8GenerateKey(viewSecretKey)
	if err != nil {
		return nil, err
	}
	buf, err = zanocrypto.ChaCha8(code, make([]byte, 8), buf)
	if err != nil {
		return nil, err
	}
	//log.Printf("decoded buffer:\n%s", hex.Dump(buf))
	r := bytes.NewReader(buf)
	res := new(FinalizeTxParam)

	err = zanobase.Deserialize(r, res)
	if err != nil {
		return nil, err
	}
	final := must(io.ReadAll(r))
	if len(final) != 0 {
		//log.Printf("remaining data:\n%s", hex.Dump(final))
		return nil, errors.New("trailing data")
	}
	return res, nil
}

type ftpSrcSorter struct {
	tx  *zanobase.Transaction
	ftp *FinalizeTxParam
}

func (res *ftpSrcSorter) Len() int {
	return len(res.tx.Vin)
}

func (res *ftpSrcSorter) Less(a, b int) bool {
	// TODO handle other types
	return bytes.Compare(res.tx.Vin[a].Value.(*zanobase.TxInZcInput).KeyImage.Bytes(), res.tx.Vin[b].Value.(*zanobase.TxInZcInput).KeyImage.Bytes()) < 0
}

func (res *ftpSrcSorter) Swap(a, b int) {
	res.tx.Vin[a], res.tx.Vin[b] = res.tx.Vin[b], res.tx.Vin[a]
	res.ftp.Sources[a], res.ftp.Sources[b] = res.ftp.Sources[b], res.ftp.Sources[a]
}
