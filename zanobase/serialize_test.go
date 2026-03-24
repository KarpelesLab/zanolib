package zanobase_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
)

func TestSerializeDeserializeUint64(t *testing.T) {
	type testStruct struct {
		Value uint64
	}

	original := testStruct{Value: 0x123456789abcdef0}
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	var decoded testStruct
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if decoded.Value != original.Value {
		t.Errorf("expected %x, got %x", original.Value, decoded.Value)
	}
}

func TestSerializeDeserializeVarintField(t *testing.T) {
	type testStruct struct {
		Value uint64 `epee:"varint"`
	}

	original := testStruct{Value: 1337}
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	var decoded testStruct
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if decoded.Value != original.Value {
		t.Errorf("expected %d, got %d", original.Value, decoded.Value)
	}
}

func TestSerializeDeserializeBool(t *testing.T) {
	type testStruct struct {
		Flag bool
	}

	for _, v := range []bool{true, false} {
		original := testStruct{Flag: v}
		buf := &bytes.Buffer{}
		if err := zanobase.Serialize(buf, &original); err != nil {
			t.Fatalf("serialize failed: %v", err)
		}
		var decoded testStruct
		if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
			t.Fatalf("deserialize failed: %v", err)
		}
		if decoded.Flag != v {
			t.Errorf("expected %v, got %v", v, decoded.Flag)
		}
	}
}

func TestSerializeDeserializeUint8(t *testing.T) {
	type testStruct struct {
		Value uint8
	}
	original := testStruct{Value: 0xab}
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}
	var decoded testStruct
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if decoded.Value != original.Value {
		t.Errorf("expected %x, got %x", original.Value, decoded.Value)
	}
}

func TestSerializeDeserializeUint16(t *testing.T) {
	type testStruct struct {
		Value uint16
	}
	original := testStruct{Value: 0x1234}
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}
	var decoded testStruct
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if decoded.Value != original.Value {
		t.Errorf("expected %x, got %x", original.Value, decoded.Value)
	}
}

func TestSerializeDeserializeByteArray32(t *testing.T) {
	type testStruct struct {
		Hash [32]byte
	}
	var original testStruct
	for i := range original.Hash {
		original.Hash[i] = byte(i)
	}
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}
	var decoded testStruct
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if decoded.Hash != original.Hash {
		t.Errorf("hash mismatch")
	}
}

func TestSerializeDeserializeString(t *testing.T) {
	type testStruct struct {
		Name string
	}
	original := testStruct{Name: "hello zano"}
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}
	var decoded testStruct
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if decoded.Name != original.Name {
		t.Errorf("expected %q, got %q", original.Name, decoded.Name)
	}
}

func TestSerializeDeserializeByteSlice(t *testing.T) {
	type testStruct struct {
		Data []byte
	}
	original := testStruct{Data: []byte{0xde, 0xad, 0xbe, 0xef}}
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}
	var decoded testStruct
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if !bytes.Equal(decoded.Data, original.Data) {
		t.Errorf("data mismatch")
	}
}

func TestSerializeDeserializeMultiField(t *testing.T) {
	type testStruct struct {
		A uint8
		B uint16
		C uint64
		D bool
	}
	original := testStruct{A: 42, B: 1000, C: 999999999, D: true}
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}
	var decoded testStruct
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if decoded != original {
		t.Errorf("expected %+v, got %+v", original, decoded)
	}
}

func TestSerializeDeserializeEdwardsPoint(t *testing.T) {
	// Use the generator point
	g := edwards25519.NewGeneratorPoint()
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, g); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}
	if buf.Len() != 32 {
		t.Fatalf("expected 32 bytes, got %d", buf.Len())
	}

	// Deserialize by reading the 32 bytes and using SetBytes
	decoded, err := new(edwards25519.Point).SetBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("SetBytes failed: %v", err)
	}
	if decoded.Equal(g) != 1 {
		t.Error("point mismatch after round-trip")
	}
}

func TestSerializeDeserializeEdwardsScalar(t *testing.T) {
	scBytes, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	sc, err := new(edwards25519.Scalar).SetCanonicalBytes(scBytes)
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, sc); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	// Deserialize by reading the 32 bytes and using SetCanonicalBytes
	decoded, err := new(edwards25519.Scalar).SetCanonicalBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("SetCanonicalBytes failed: %v", err)
	}
	if decoded.Equal(sc) != 1 {
		t.Error("scalar mismatch after round-trip")
	}
}

func TestPointReadWriteRoundTrip(t *testing.T) {
	g := edwards25519.NewGeneratorPoint()
	p := &zanobase.Point{Point: g}

	buf := &bytes.Buffer{}
	_, err := p.WriteTo(buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if buf.Len() != 32 {
		t.Fatalf("expected 32 bytes, got %d", buf.Len())
	}

	p2 := &zanobase.Point{}
	_, err = p2.ReadFrom(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if p2.Point.Equal(g) != 1 {
		t.Error("point mismatch after read/write round-trip")
	}
}

func TestPointMarshalJSON(t *testing.T) {
	g := edwards25519.NewGeneratorPoint()
	p := &zanobase.Point{Point: g}

	data, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if s != hex.EncodeToString(g.Bytes()) {
		t.Errorf("unexpected JSON value: %s", s)
	}
}

func TestPointMarshalJSONNil(t *testing.T) {
	p := &zanobase.Point{}
	data, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	if string(data) != "null" {
		t.Errorf("expected null, got %s", string(data))
	}
}

func TestScalarReadWriteRoundTrip(t *testing.T) {
	scBytes, _ := hex.DecodeString("0500000000000000000000000000000000000000000000000000000000000000")
	sc, _ := new(edwards25519.Scalar).SetCanonicalBytes(scBytes)
	s := &zanobase.Scalar{Scalar: sc}

	buf := &bytes.Buffer{}
	_, err := s.WriteTo(buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	s2 := &zanobase.Scalar{}
	_, err = s2.ReadFrom(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if s2.Scalar.Equal(sc) != 1 {
		t.Error("scalar mismatch after read/write round-trip")
	}
}

func TestScalarMarshalJSON(t *testing.T) {
	scBytes, _ := hex.DecodeString("0300000000000000000000000000000000000000000000000000000000000000")
	sc, _ := new(edwards25519.Scalar).SetCanonicalBytes(scBytes)
	s := &zanobase.Scalar{Scalar: sc}

	data, err := s.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if str != hex.EncodeToString(sc.Bytes()) {
		t.Errorf("unexpected JSON value: %s", str)
	}
}

func TestScalarMarshalJSONNil(t *testing.T) {
	s := &zanobase.Scalar{}
	data, err := s.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	if string(data) != "null" {
		t.Errorf("expected null, got %s", string(data))
	}
}

func TestValue256(t *testing.T) {
	var v zanobase.Value256
	for i := range v {
		v[i] = byte(i)
	}

	// Test Bytes()
	b := v.Bytes()
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}

	// Test String()
	s := v.String()
	if s != hex.EncodeToString(v[:]) {
		t.Errorf("String() mismatch: %s", s)
	}

	// Test IsZero()
	if v.IsZero() {
		t.Error("non-zero value reported as zero")
	}
	var zero zanobase.Value256
	if !zero.IsZero() {
		t.Error("zero value reported as non-zero")
	}

	// Test B32()
	b32 := v.B32()
	if b32 != [32]byte(v) {
		t.Error("B32() mismatch")
	}

	// Test PB32()
	pb32 := v.PB32()
	if *pb32 != [32]byte(v) {
		t.Error("PB32() mismatch")
	}

	// Test MarshalJSON()
	data, err := v.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	var js string
	if err := json.Unmarshal(data, &js); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if js != s {
		t.Errorf("JSON mismatch: %s != %s", js, s)
	}

	// Test ReadFrom()
	var v2 zanobase.Value256
	_, err = v2.ReadFrom(bytes.NewReader(v[:]))
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if v2 != v {
		t.Error("ReadFrom mismatch")
	}
}

func TestValue256ToPoint(t *testing.T) {
	// Use the generator point bytes
	g := edwards25519.NewGeneratorPoint()
	var v zanobase.Value256
	copy(v[:], g.Bytes())

	pt := v.ToPoint()
	if pt == nil {
		t.Fatal("ToPoint returned nil")
	}
	if pt.Equal(g) != 1 {
		t.Error("ToPoint result doesn't match generator")
	}

	// Test with invalid point bytes — high bit set with non-canonical encoding
	var invalid zanobase.Value256
	for i := range invalid {
		invalid[i] = 0xee
	}
	invalid[31] = 0xff // set high bytes to make it non-canonical
	pt = invalid.ToPoint()
	if pt != nil {
		t.Error("expected nil for invalid point bytes")
	}
}

func TestVarintRoundTrip(t *testing.T) {
	vectors := []uint64{0, 1, 42, 127, 255, 1337, 0x123456789, 0xabcdef123456789}

	for _, v := range vectors {
		vi := zanobase.Varint(v)
		b := vi.Bytes()

		// ReadFrom round-trip
		var vi2 zanobase.Varint
		_, err := vi2.ReadFrom(bytes.NewReader(b))
		if err != nil {
			t.Errorf("varint %d: ReadFrom failed: %v", v, err)
			continue
		}
		if uint64(vi2) != v {
			t.Errorf("varint %d: got %d", v, uint64(vi2))
		}
	}
}

func TestVariantFor(t *testing.T) {
	// Test creating a variant for a known type
	gen := &zanobase.TxInGen{Height: 42}
	v := zanobase.VariantFor(gen)
	if v.Tag != zanobase.TagGen {
		t.Errorf("expected tag %d, got %d", zanobase.TagGen, v.Tag)
	}

	// Extract it back
	got := zanobase.VariantAs[*zanobase.TxInGen](v)
	if got.Height != 42 {
		t.Errorf("expected height 42, got %d", got.Height)
	}
}

func TestVariantMarshalJSON(t *testing.T) {
	gen := &zanobase.TxInGen{Height: 100}
	v := zanobase.VariantFor(gen)
	data, err := v.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	// Should contain "type":"gen"
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	var typ string
	if err := json.Unmarshal(m["type"], &typ); err != nil {
		t.Fatalf("JSON unmarshal type failed: %v", err)
	}
	if typ != "gen" {
		t.Errorf("expected type 'gen', got %q", typ)
	}
}

func TestTagFor(t *testing.T) {
	tests := []struct {
		name string
		tag  zanobase.Tag
	}{
		{"TxInGen", zanobase.TagGen},
		{"TxInZcInput", zanobase.TagTxinZcInput},
		{"TxOutZarcanium", zanobase.TagTxOutZarcanum},
		{"ZCSig", zanobase.TagZCSig},
	}
	// Verify Tag.New() and Tag.Type() don't panic for known tags
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = tt.tag.New()
			_ = tt.tag.Type()
		})
	}
}

func TestReadVarBytes(t *testing.T) {
	data := []byte{0x04, 0xde, 0xad, 0xbe, 0xef}
	result, err := zanobase.ReadVarBytes(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadVarBytes failed: %v", err)
	}
	if !bytes.Equal(result, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("unexpected result: %x", result)
	}
}

func TestReadVarBytesEmpty(t *testing.T) {
	data := []byte{0x00}
	result, err := zanobase.ReadVarBytes(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadVarBytes failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty, got %x", result)
	}
}

func TestReadVec32(t *testing.T) {
	// 1 element
	var val [32]byte
	for i := range val {
		val[i] = byte(i)
	}
	data := append([]byte{0x01}, val[:]...)
	result, err := zanobase.ReadVec32(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadVec32 failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 element, got %d", len(result))
	}
	if result[0] != zanobase.Value256(val) {
		t.Error("value mismatch")
	}
}

func TestGenContextResize(t *testing.T) {
	gc := &zanobase.GenContext{}
	gc.Resize(3, 5)
	if len(gc.AssetIds) != 5 {
		t.Errorf("expected AssetIds len 5, got %d", len(gc.AssetIds))
	}
	if len(gc.ZcInputAmounts) != 3 {
		t.Errorf("expected ZcInputAmounts len 3, got %d", len(gc.ZcInputAmounts))
	}
	// Resize down
	gc.Resize(1, 2)
	if len(gc.AssetIds) != 2 {
		t.Errorf("expected AssetIds len 2, got %d", len(gc.AssetIds))
	}
}

func TestSerializeDeserializeVariant(t *testing.T) {
	gen := &zanobase.TxInGen{Height: 12345}
	v := zanobase.VariantFor(gen)

	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, v); err != nil {
		t.Fatalf("serialize variant failed: %v", err)
	}

	var decoded zanobase.Variant
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize variant failed: %v", err)
	}
	if decoded.Tag != zanobase.TagGen {
		t.Errorf("expected tag %d, got %d", zanobase.TagGen, decoded.Tag)
	}
	got := zanobase.VariantAs[*zanobase.TxInGen](&decoded)
	if got.Height != 12345 {
		t.Errorf("expected height 12345, got %d", got.Height)
	}
}

func TestSerializeDeserializeAccountPublicAddr(t *testing.T) {
	original := zanobase.AccountPublicAddr{
		Flags: 1,
	}
	for i := range original.SpendKey {
		original.SpendKey[i] = byte(i)
	}
	for i := range original.ViewKey {
		original.ViewKey[i] = byte(32 + i)
	}

	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	var decoded zanobase.AccountPublicAddr
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if decoded.SpendKey != original.SpendKey {
		t.Error("SpendKey mismatch")
	}
	if decoded.ViewKey != original.ViewKey {
		t.Error("ViewKey mismatch")
	}
	if decoded.Flags != original.Flags {
		t.Errorf("Flags: expected %d, got %d", original.Flags, decoded.Flags)
	}
}

func TestSerializeDeserializeTxOutZarcanium(t *testing.T) {
	original := zanobase.TxOutZarcanium{
		EncryptedAmount: 42,
		MixAttr:         1,
	}
	for i := range original.StealthAddress {
		original.StealthAddress[i] = byte(i)
	}

	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	var decoded zanobase.TxOutZarcanium
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if decoded.StealthAddress != original.StealthAddress {
		t.Error("StealthAddress mismatch")
	}
	if decoded.EncryptedAmount != original.EncryptedAmount {
		t.Error("EncryptedAmount mismatch")
	}
	if decoded.MixAttr != original.MixAttr {
		t.Error("MixAttr mismatch")
	}
}

func TestSerializeDeserializeZarcaniumTxDataV1(t *testing.T) {
	original := zanobase.ZarcaniumTxDataV1{Fee: 10000}
	buf := &bytes.Buffer{}
	if err := zanobase.Serialize(buf, &original); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	var decoded zanobase.ZarcaniumTxDataV1
	if err := zanobase.Deserialize(bytes.NewReader(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if decoded.Fee != original.Fee {
		t.Errorf("expected fee %d, got %d", original.Fee, decoded.Fee)
	}
}

func TestTransactionGetFee(t *testing.T) {
	tx := &zanobase.Transaction{
		Extra: []*zanobase.Variant{
			zanobase.VariantFor(&zanobase.ZarcaniumTxDataV1{Fee: 5000}),
		},
	}
	fee, ok := tx.GetFee()
	if !ok {
		t.Fatal("GetFee returned false")
	}
	if fee != 5000 {
		t.Errorf("expected fee 5000, got %d", fee)
	}
}

func TestTransactionGetFeeNotFound(t *testing.T) {
	tx := &zanobase.Transaction{}
	_, ok := tx.GetFee()
	if ok {
		t.Error("expected GetFee to return false for tx without fee")
	}
}

func TestTransactionPrefix(t *testing.T) {
	tx := &zanobase.Transaction{
		Version: 2,
		Vin: []*zanobase.Variant{
			zanobase.VariantFor(&zanobase.TxInGen{Height: 100}),
		},
	}
	prefix := tx.Prefix()
	if uint64(prefix.Version) != 2 {
		t.Errorf("expected version 2, got %d", prefix.Version)
	}
	if len(prefix.Vin) != 1 {
		t.Errorf("expected 1 vin, got %d", len(prefix.Vin))
	}
}

func TestVarintReadUnexpectedEOF(t *testing.T) {
	// A varint with continuation bit set but no more data
	data := []byte{0x80}
	var vi zanobase.Varint
	_, err := vi.ReadFrom(bytes.NewReader(data))
	if err == nil {
		t.Error("expected error for truncated varint")
	}
}
