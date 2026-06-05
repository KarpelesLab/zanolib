package zanobase

import "reflect"

// Tag is an 8-bit discriminator used to identify the concrete type stored
// in a [Variant]. Each tag value maps to a specific Go type.
type Tag uint8

type tagDefinition struct {
	typ  reflect.Type
	name string
}

var (
	variantTags   = make(map[Tag]*tagDefinition)
	tagNameLookup = make(map[string]Tag)
	tagTypeLookup = make(map[reflect.Type]Tag)
)

// Variant tag values, matching the SET_VARIANT_TAGS table in zano's
// src/currency_core/currency_basic.h.
const (
	TagGen                    Tag = 0
	TagToKey                  Tag = 1
	TagComment                Tag = 7
	TagCryptoChecksum         Tag = 10
	TagDerivationHint         Tag = 11
	TagServiceAttachment      Tag = 12
	TagUnlockTime             Tag = 14
	TagExpirationTime         Tag = 15
	TagTxFlags                Tag = 16
	TagSignedParts            Tag = 17
	TagExtraAttachmentInfo    Tag = 18
	TagUserData               Tag = 19
	TagExtraPadding           Tag = 21
	TagPubKey                 Tag = 22
	TagEtcTxFlags16           Tag = 23
	TagDeriveXor              Tag = 24
	TagRefById                Tag = 25
	TagUint64                 Tag = 26
	TagEtcTxTime              Tag = 27
	TagUint32                 Tag = 28
	TagPayer                  Tag = 31
	TagReceiver               Tag = 32
	TagTxinZcInput            Tag = 37
	TagTxOutZarcanum          Tag = 38
	TagZarcaniumTxDataV1      Tag = 39
	TagZCSig                  Tag = 43
	TagZcAssetSurjectionProof Tag = 46
	TagZcOutsRangeProof       Tag = 47
	TagZcBalanceProof         Tag = 48
)

func defTag[T any](tag Tag, name string) {
	variantTags[tag] = &tagDefinition{
		typ:  reflect.TypeFor[T](),
		name: name,
	}
	tagNameLookup[name] = tag

	t := reflect.TypeFor[T]()
	tagTypeLookup[t] = tag
}

func init() {
	defTag[*TxInGen](TagGen, "gen")
	defTag[*TxInToKey](TagToKey, "key")
	defTag[*TxComment](TagComment, "comment")
	defTag[*TxCryptoChecksum](TagCryptoChecksum, "checksum")
	defTag[[]byte](TagDerivationHint, "derivation_hint")
	defTag[*TxServiceAttachment](TagServiceAttachment, "attachment")
	defTag[*EtcTxDetailsUnlockTime](TagUnlockTime, "unlock_time")
	defTag[*EtcTxDetailsExpirationTime](TagExpirationTime, "expiration_time")
	defTag[*EtcTxDetailsFlags](TagTxFlags, "flags")
	defTag[*SignedParts](TagSignedParts, "signed_outs")
	defTag[*ExtraAttachmentInfo](TagExtraAttachmentInfo, "extra_attach_info")
	defTag[*ExtraUserData](TagUserData, "user_data")
	defTag[*ExtraPadding](TagExtraPadding, "extra_padding")
	defTag[Value256](TagPubKey, "pub_key")
	defTag[uint16](TagEtcTxFlags16, "etc_tx_flags16")
	defTag[uint16](TagDeriveXor, "derive_xor")
	defTag[*RefById](TagRefById, "ref_by_id")
	defTag[uint64](TagUint64, "uint64_t")
	defTag[*EtcTxTime](TagEtcTxTime, "etc_tx_time")
	defTag[uint32](TagUint32, "uint32_t")
	defTag[*TxPayer](TagPayer, "payer2")
	defTag[*TxReceiver](TagReceiver, "receiver2")
	defTag[*TxInZcInput](TagTxinZcInput, "txin_zc_input")
	defTag[*TxOutZarcanium](TagTxOutZarcanum, "tx_out_zarcanum")
	defTag[*ZarcaniumTxDataV1](TagZarcaniumTxDataV1, "zarcanum_tx_data_v1")
	defTag[*ZCSig](TagZCSig, "ZC_sig")
	defTag[*ZCAssetSurjectionProof](TagZcAssetSurjectionProof, "zc_asset_surjection_proof")
	defTag[*ZCOutsRangeProof](TagZcOutsRangeProof, "zc_outs_range_proof")
	defTag[*ZCBalanceProof](TagZcBalanceProof, "zc_balance_proof")
}

// TagFor returns the [Tag] registered for type T, or 0xff if T is not registered.
func TagFor[T any]() Tag {
	t := reflect.TypeFor[T]()
	if tag, ok := tagTypeLookup[t]; ok {
		return tag
	}
	return Tag(0xff)
}

// New creates a new zero-value instance of the type registered for this tag.
// Panics if the tag is not registered.
func (t Tag) New() any {
	def, ok := variantTags[t]
	if !ok {
		panic("invalid tag")
	}
	return reflect.New(def.typ).Elem().Interface()
}

// Type returns the reflect.Type registered for this tag.
// Panics if the tag is not registered.
func (t Tag) Type() reflect.Type {
	def, ok := variantTags[t]
	if !ok {
		panic("invalid tag")
	}
	return def.typ
}

// TypeOK returns the reflect.Type registered for this tag, and whether it is
// registered. Unlike [Tag.Type], it does not panic on unknown tags, so callers
// (such as the deserializer) can surface a clean error when encountering a
// variant type this library does not yet understand.
func (t Tag) TypeOK() (reflect.Type, bool) {
	def, ok := variantTags[t]
	if !ok {
		return nil, false
	}
	return def.typ, true
}
