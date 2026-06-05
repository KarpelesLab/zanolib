package zanobase

import (
	"io"

	"github.com/KarpelesLab/rc"
	"golang.org/x/crypto/sha3"
)

// Transaction version constants, mirroring TRANSACTION_VERSION_* in zano's
// src/currency_core/currency_config.h.
const (
	TransactionVersionInitial = 0 // TRANSACTION_VERSION_INITAL
	TransactionVersionPreHF4  = 1 // TRANSACTION_VERSION_PRE_HF4
	TransactionVersionPostHF4 = 2 // TRANSACTION_VERSION_POST_HF4
	TransactionVersionPostHF5 = 3 // TRANSACTION_VERSION_POST_HF5 (adds hardfork_id to the prefix)
)

// TransactionPrefix contains the hashable prefix of a transaction: version,
// inputs, extra fields, outputs, and (for version >= 3) the hardfork id.
type TransactionPrefix struct {
	Version    Varint     `json:"version"`     // varint
	Vin        []*Variant `json:"vin"`         // txin_v = boost::variant<txin_gen[0], txin_to_key[1], txin_multisig[2], txin_htlc[34], txin_zc_input[37]>
	Extra      []*Variant `json:"extra"`       // extra_v
	Vout       []*Variant `json:"vout"`        // tx_out_v = boost::variant<tx_out_bare[36], tx_out_zarcanum[38]>
	HardforkId uint8      `json:"hardfork_id"` // uint8_t, only serialized when Version >= TransactionVersionPostHF5
}

// Transaction represents a complete Zano transaction including the prefix,
// attachments, signatures, and proofs.
type Transaction struct {
	Version Varint     `json:"version"` // varint
	Vin     []*Variant `json:"vin"`     // txin_v = boost::variant<txin_gen[0], txin_to_key[1], txin_multisig[2], txin_htlc[34], txin_zc_input[37]>
	Extra   []*Variant `json:"extra"`   // extra_v
	Vout    []*Variant `json:"vout"`    // tx_out_v = boost::variant<tx_out_bare[36], tx_out_zarcanum[38]>
	// hardfork_id is part of the prefix (serialized after Vout) for version >= 3
	HardforkId uint8 `json:"hardfork_id,omitempty"` // uint8_t
	// up to here this was transaction_prefix
	Attachment []*Variant `json:"attachment,omitempty"`
	Signatures []*Variant `json:"signatures"` // signature_v = boost::variant<NLSAG_sig, void_sig, ZC_sig, zarcanum_sig>
	Proofs     []*Variant `json:"proofs"`     // proof_v
}

// Prefix returns the hashable prefix portion of the transaction.
func (tx *Transaction) Prefix() *TransactionPrefix {
	return &TransactionPrefix{
		Version:    tx.Version,
		Vin:        tx.Vin,
		Extra:      tx.Extra,
		Vout:       tx.Vout,
		HardforkId: tx.HardforkId,
	}
}

// WriteTo serializes the transaction prefix. The hardfork_id byte is only
// written for version >= TransactionVersionPostHF5, matching the conditional
// in currency::transaction_prefix::BEGIN_SERIALIZE().
func (txp *TransactionPrefix) WriteTo(w io.Writer) (int64, error) {
	cw := &countWriter{w: w}
	err := serializeFields(cw, txp.Version, txp.Vin, txp.Extra, txp.Vout)
	if err != nil {
		return cw.n, err
	}
	if uint64(txp.Version) >= TransactionVersionPostHF5 {
		if err = Serialize(cw, txp.HardforkId); err != nil {
			return cw.n, err
		}
	}
	return cw.n, nil
}

// ReadFrom deserializes the transaction prefix, reading the hardfork_id byte
// only for version >= TransactionVersionPostHF5.
func (txp *TransactionPrefix) ReadFrom(r io.Reader) (int64, error) {
	// rc.New yields a ByteAndReadReader so Deserialize reuses it directly
	// instead of wrapping each field read in a fresh (read-ahead) bufio.Reader.
	cr := rc.New(r)
	err := deserializeFields(cr, &txp.Version, &txp.Vin, &txp.Extra, &txp.Vout)
	if err != nil {
		return cr.Error64(err)
	}
	if uint64(txp.Version) >= TransactionVersionPostHF5 {
		if err = Deserialize(cr, &txp.HardforkId); err != nil {
			return cr.Error64(err)
		}
	}
	return cr.Ret64()
}

// WriteTo serializes the full transaction. The hardfork_id byte is part of the
// prefix (written after Vout) and only present for version >= 3.
func (tx *Transaction) WriteTo(w io.Writer) (int64, error) {
	cw := &countWriter{w: w}
	err := serializeFields(cw, tx.Version, tx.Vin, tx.Extra, tx.Vout)
	if err != nil {
		return cw.n, err
	}
	if uint64(tx.Version) >= TransactionVersionPostHF5 {
		if err = Serialize(cw, tx.HardforkId); err != nil {
			return cw.n, err
		}
	}
	if err = serializeFields(cw, tx.Attachment, tx.Signatures, tx.Proofs); err != nil {
		return cw.n, err
	}
	return cw.n, nil
}

// ReadFrom deserializes the full transaction, reading the hardfork_id byte
// (after Vout) only for version >= 3.
func (tx *Transaction) ReadFrom(r io.Reader) (int64, error) {
	cr := rc.New(r)
	err := deserializeFields(cr, &tx.Version, &tx.Vin, &tx.Extra, &tx.Vout)
	if err != nil {
		return cr.Error64(err)
	}
	if uint64(tx.Version) >= TransactionVersionPostHF5 {
		if err = Deserialize(cr, &tx.HardforkId); err != nil {
			return cr.Error64(err)
		}
	}
	if err = deserializeFields(cr, &tx.Attachment, &tx.Signatures, &tx.Proofs); err != nil {
		return cr.Error64(err)
	}
	return cr.Ret64()
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

// serializeFields serializes each field in order using the package serializer.
func serializeFields(w io.Writer, fields ...any) error {
	for _, f := range fields {
		if err := Serialize(w, f); err != nil {
			return err
		}
	}
	return nil
}

// deserializeFields deserializes into each target pointer in order.
func deserializeFields(r io.Reader, targets ...any) error {
	for _, t := range targets {
		if err := Deserialize(r, t); err != nil {
			return err
		}
	}
	return nil
}

// countWriter wraps an io.Writer and tracks the number of bytes written, so
// WriteTo implementations can report an accurate count.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
