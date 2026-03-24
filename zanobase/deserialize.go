package zanobase

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/rc"
)

var (
	readerFromType = reflect.TypeFor[io.ReaderFrom]()
	byteArrayType  = reflect.TypeFor[[]byte]()
	variantType    = reflect.TypeFor[Variant]()
)

// Deserialize reads EPEE binary data from rx and populates target.
// It handles structs via reflection, slices with varint-prefixed lengths,
// and primitive types. Types implementing io.ReaderFrom are handled directly.
func Deserialize(rx io.Reader, target any) error {
	var err error
	var buf rc.ByteAndReadReader
	if v, ok := rx.(rc.ByteAndReadReader); ok {
		buf = v
	} else {
		buf = bufio.NewReader(rx)
	}

	var obj reflect.Value
	if v, ok := target.(reflect.Value); ok {
		obj = v
	} else {
		obj = reflect.ValueOf(target)
	}
	t := obj.Type()

	for t.Kind() == reflect.Ptr || t.Kind() == reflect.Interface {
		if t.Kind() == reflect.Ptr && obj.IsNil() {
			obj.Set(reflect.New(t.Elem()))
		}
		if t.Implements(readerFromType) {
			_, err = obj.Interface().(io.ReaderFrom).ReadFrom(buf)
			return err
		}
		obj = obj.Elem()
		t = obj.Type()
	}
	if t == byteArrayType {
		return subDeserialize(buf, obj.Addr().Interface(), "!")
	}
	if t == variantType {
		return subDeserialize(buf, obj.Addr().Interface(), "!")
	}
	if t.Kind() == reflect.Slice {
		ln, err := VarintReadUint64(buf)
		if err != nil {
			return err
		}
		if ln > 128 {
			return fmt.Errorf("slice too large: %d > 128", ln)
		}
		val := reflect.MakeSlice(t, int(ln), int(ln))
		for i := 0; i < int(ln); i++ {
			err = subDeserialize(buf, val.Index(i).Addr().Interface(), "")
			if err != nil {
				return err
			}
		}
		obj.Set(val)
		return nil
	}
	if t.Kind() != reflect.Struct {
		return subDeserialize(buf, obj.Addr().Interface(), "!")
	}

	nf := t.NumField()
	for i := 0; i < nf; i += 1 {
		tf := t.Field(i)
		if !tf.IsExported() {
			continue
		}
		tag := tf.Tag.Get("epee")
		err = subDeserialize(buf, obj.Field(i).Addr().Interface(), tag)
		if err != nil {
			return err
		}
	}
	return nil
}

func subDeserialize(r rc.ByteAndReadReader, o any, tag string) error {
	var err error
	switch v := o.(type) {
	case *bool, *uint8, *uint16:
		err = binary.Read(r, binary.LittleEndian, v)
	case *uint64:
		if tag == "varint" {
			*v, err = VarintReadUint64(r)
		} else {
			err = binary.Read(r, binary.LittleEndian, v)
		}
	case *[32]byte:
		_, err = io.ReadFull(r, v[:])
	case *string:
		ln, err := VarintReadUint64(r)
		if err != nil {
			return err
		}
		if ln > 4096 {
			return fmt.Errorf("string length too long: %d", ln)
		}
		buf := make([]byte, ln)
		_, err = io.ReadFull(r, buf)
		if err != nil {
			return err
		}
		*v = string(buf)
		return nil
	case *[]byte:
		ln, err := VarintReadUint64(r)
		if err != nil {
			return err
		}
		if ln > 4096 {
			return fmt.Errorf("string length too long: %d", ln)
		}
		*v = make([]byte, ln)
		_, err = io.ReadFull(r, *v)
		if err != nil {
			return err
		}
		return nil
	case *Variant:
		tagV, err := r.ReadByte()
		if err != nil {
			return err
		}
		tag := Tag(tagV)
		v.Tag = tag
		typ := tag.Type()
		obj := reflect.New(typ)
		err = Deserialize(r, obj)
		if err != nil {
			return err
		}
		v.Value = obj.Elem().Interface()
		return nil
	case *edwards25519.Point:
		buf := make([]byte, 32)
		_, err = io.ReadFull(r, buf)
		if err != nil {
			return err
		}
		_, err = v.SetBytes(buf)
		return err
	case *edwards25519.Scalar:
		buf := make([]byte, 32)
		_, err = io.ReadFull(r, buf)
		if err != nil {
			return err
		}
		_, err = v.SetCanonicalBytes(buf)
		return err
	default:
		if tag == "!" {
			return fmt.Errorf("unsupported deserialize type %T", o)
		}
		err = Deserialize(r, v)

	}
	return err
}
