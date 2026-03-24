package zanobase

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"

	"filippo.io/edwards25519"
)

type byter interface {
	Bytes() []byte
}

var (
	byterType    = reflect.TypeFor[byter]()
	writerToType = reflect.TypeFor[io.WriterTo]()
)

// Serialize writes the EPEE binary serialization of source to w. It handles
// structs via reflection, slices with varint-prefixed lengths, and primitive
// types. Types implementing io.WriterTo or the byter interface are handled
// directly.
func Serialize(w io.Writer, source any) error {
	obj := reflect.ValueOf(source)
	t := obj.Type()

	for t.Kind() == reflect.Ptr {
		if t.Implements(writerToType) {
			_, err := obj.Interface().(io.WriterTo).WriteTo(w)
			return err
		}
		if t.Implements(byterType) {
			buf := obj.Interface().(byter).Bytes()
			_, err := w.Write(buf)
			return err
		}
		obj = obj.Elem()
		t = obj.Type()
	}
	if t == byteArrayType {
		return subSerialize(w, obj.Interface(), "!")
	}
	if t == variantType {
		return subSerialize(w, obj.Interface(), "!")
	}
	if t.Kind() == reflect.Slice {
		ln := obj.Len()
		_, err := w.Write(Varint(ln).Bytes())
		if err != nil {
			return err
		}
		for i := 0; i < ln; i++ {
			err = Serialize(w, obj.Index(i).Interface())
			if err != nil {
				return err
			}
		}
		return nil
	}
	if t.Kind() != reflect.Struct {
		return subSerialize(w, obj.Interface(), "!")
	}

	nf := t.NumField()
	for i := 0; i < nf; i += 1 {
		tf := t.Field(i)
		if !tf.IsExported() {
			continue
		}
		tag := tf.Tag.Get("epee")
		err := subSerialize(w, obj.Field(i).Interface(), tag)
		if err != nil {
			return err
		}
	}
	return nil
}

func subSerialize(w io.Writer, o any, tag string) error {
	var err error
	switch v := o.(type) {
	case bool, uint8, uint16:
		err = binary.Write(w, binary.LittleEndian, v)
	case uint64:
		if tag == "varint" {
			_, err = w.Write(Varint(v).Bytes())
		} else {
			err = binary.Write(w, binary.LittleEndian, v)
		}
	case [32]byte:
		_, err = w.Write(v[:])
	case string:
		ln := len(v)
		_, err = w.Write(Varint(ln).Bytes())
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(v))
	case []byte:
		ln := len(v)
		_, err = w.Write(Varint(ln).Bytes())
		if err != nil {
			return err
		}
		_, err = w.Write(v)
	case byter:
		_, err = w.Write(v.Bytes())
	case Variant:
		_, err = w.Write([]byte{byte(v.Tag)})
		if err != nil {
			return err
		}
		return Serialize(w, v.Value)
	case edwards25519.Point:
		_, err = w.Write(v.Bytes())
	case edwards25519.Scalar:
		_, err = w.Write(v.Bytes())
	default:
		if tag == "!" {
			return fmt.Errorf("unsupported serialize type %T", o)
		}
		err = Serialize(w, v)

	}
	return err
}
