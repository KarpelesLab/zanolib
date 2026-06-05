package zanobase

// This file defines the additional tx_extra / attachment / etc-details variant
// types that appear in on-chain transactions (coinbase, PoS, and transfers with
// payloads). They mirror the corresponding structs in zano's
// src/currency_core/currency_basic.h; field order and varint/fixed encoding must
// match each struct's BEGIN_SERIALIZE() exactly.

// ExtraUserData carries arbitrary user data placed in tx extra (e.g. a mining
// pool signature). currency::extra_user_data { std::string buff; }
type ExtraUserData struct {
	Buff []byte `json:"buff"`
}

// ExtraPadding is zero/stub padding in tx extra.
// currency::extra_padding { std::vector<uint8_t> buff; }
type ExtraPadding struct {
	Buff []byte `json:"buff"`
}

// EtcTxDetailsUnlockTime is a global unlock time stored in tx extra.
// currency::etc_tx_details_unlock_time { uint64_t v; } // VARINT
type EtcTxDetailsUnlockTime struct {
	V uint64 `json:"v" epee:"varint"`
}

// EtcTxDetailsExpirationTime is a tx expiration time stored in tx extra.
// currency::etc_tx_details_expiration_time { uint64_t v; } // VARINT
type EtcTxDetailsExpirationTime struct {
	V uint64 `json:"v" epee:"varint"`
}

// EtcTxDetailsFlags carries miscellaneous tx flags stored in tx extra.
// currency::etc_tx_details_flags { uint64_t v; } // VARINT
type EtcTxDetailsFlags struct {
	V uint64 `json:"v" epee:"varint"`
}

// EtcTxTime is a tx timestamp stored in tx extra.
// currency::etc_tx_time { uint64_t v; } // VARINT
type EtcTxTime struct {
	V uint64 `json:"v" epee:"varint"`
}

// ExtraAttachmentInfo describes the attached payload (size, hash, count). It is
// a member of both extra_v and txin_etc_details_v.
// currency::extra_attachment_info { uint64_t sz /*VARINT*/; crypto::hash hsh; uint64_t cnt /*VARINT*/; }
type ExtraAttachmentInfo struct {
	Sz  uint64   `json:"sz" epee:"varint"`
	Hsh Value256 `json:"hsh"`
	Cnt uint64   `json:"cnt" epee:"varint"`
}

// SignedParts records how many outputs/extras a given input signs over, used in
// separately-signed (consolidated) transactions. Member of txin_etc_details_v.
// currency::signed_parts { uint64_t n_outs /*VARINT*/; uint64_t n_extras /*VARINT*/; }
type SignedParts struct {
	NOuts   uint64 `json:"n_outs" epee:"varint"`
	NExtras uint64 `json:"n_extras" epee:"varint"`
}

// TxComment is an (optionally encrypted) free-form comment attachment.
// currency::tx_comment { std::string comment; }
type TxComment struct {
	Comment []byte `json:"comment"`
}

// TxCryptoChecksum carries the tx key derivation (encrypted on the sender's
// secret send key) so the sender can later decrypt attachments, plus a 32-bit
// hash for validation. Present in transactions with encrypted payloads.
// currency::tx_crypto_checksum { crypto::key_derivation encrypted_key_derivation; uint32_t derivation_hash; }
type TxCryptoChecksum struct {
	EncryptedKeyDerivation Value256 `json:"encrypted_key_derivation"`
	DerivationHash         uint32   `json:"derivation_hash"`
}

// TxPayer holds the (chacha-encrypted) sender account address attachment.
// currency::tx_payer { account_public_address acc_addr; }
type TxPayer struct {
	AccAddr AccountPublicAddr `json:"acc_addr"`
}

// TxReceiver holds the (chacha-encrypted) receiver account address attachment.
// currency::tx_receiver { account_public_address acc_addr; }
type TxReceiver struct {
	AccAddr AccountPublicAddr `json:"acc_addr"`
}

// TxServiceAttachment is a generic service payload. Notably, the integrated
// address payment ID is carried as a service attachment with ServiceId == "P"
// (BC_PAYMENT_ID_SERVICE_ID) whose Body is chacha-encrypted with the income
// key derivation when Flags & TxServiceAttachmentEncryptBody is set.
//
//	currency::tx_service_attachment {
//	  std::string service_id; std::string instruction; std::string body;
//	  std::vector<crypto::public_key> security; uint8_t flags; }
type TxServiceAttachment struct {
	ServiceId   string     `json:"service_id"`
	Instruction string     `json:"instruction"`
	Body        []byte     `json:"body"`
	Security    []Value256 `json:"security"`
	Flags       uint8      `json:"flags"`
}

// tx_service_attachment flags (see currency_basic.h).
const (
	TxServiceAttachmentEncryptBody                 = 1 << 0 // body is chacha-encrypted
	TxServiceAttachmentDeflateBody                 = 1 << 1 // body is zlib-deflated
	TxServiceAttachmentEncryptBodyIsolateAuditable = 1 << 2
	TxServiceAttachmentEncryptAddProof             = 1 << 3
)

// PaymentIdServiceId is the service_id used to carry integrated-address payment
// IDs in a TxServiceAttachment (BC_PAYMENT_ID_SERVICE_ID in zano).
const PaymentIdServiceId = "P"
