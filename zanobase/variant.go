package zanobase

import (
	"encoding/json"
	"fmt"
)

// Variant is a tagged union type analogous to C++ boost::variant, used
// throughout Zano's serialization format to represent polymorphic values.
type Variant struct {
	Tag   Tag
	Value any // any type stored as a boost::variant
}

// Payload type is actually Variant
//
// Deprecated: use Variant, this will be removed
type Payload = Variant

type marshalledVariant struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

// MarshalJSON encodes the variant as a JSON object with "type" and "value" fields.
func (p *Variant) MarshalJSON() ([]byte, error) {
	obj := &marshalledVariant{
		Value: p.Value,
	}
	if v, ok := variantTags[p.Tag]; ok {
		obj.Type = v.name
	} else {
		obj.Type = fmt.Sprintf("unknown#%d", p.Tag)
	}
	return json.Marshal(obj)
}

// VariantFor creates a new [Variant] with the correct tag for the given type T.
func VariantFor[T any](obj T) *Variant {
	return &Variant{Tag: TagFor[T](), Value: obj}
}

// VariantAs extracts the value from a [Variant] as type T. Panics if the
// value is not of the expected type.
func VariantAs[T any](p *Variant) T {
	return p.Value.(T)
}
