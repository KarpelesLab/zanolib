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

const (
	TagGen                    Tag = 0
	TagDerivationHint         Tag = 11
	TagPubKey                 Tag = 22
	TagEtcTxFlags16           Tag = 23
	TagDeriveXor              Tag = 24
	TagRefById                Tag = 25
	TagUint64                 Tag = 26
	TagUint32                 Tag = 28
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
	defTag[[]byte](TagDerivationHint, "derivation_hint")
	defTag[Value256](TagPubKey, "pub_key")
	defTag[uint16](TagEtcTxFlags16, "etc_tx_flags16")
	defTag[uint16](TagDeriveXor, "derive_xor")
	defTag[*RefById](TagRefById, "ref_by_id")
	defTag[uint64](TagUint64, "uint64_t")
	defTag[uint32](TagUint32, "uint32_t")
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
