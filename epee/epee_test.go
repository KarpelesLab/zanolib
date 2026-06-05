package epee

import "testing"

func TestRoundTrip(t *testing.T) {
	dist := NewSection().Set("amount", uint64(0)).Set("global_offsets", []uint64{1, 3, 5928, 2811})
	root := NewSection().
		Set("amounts", []*Section{dist}).
		Set("height_upper_limit", uint64(2555000)).
		Set("use_forced_mix_outs", false).
		Set("coinbase_percents", uint64(15)).
		Set("blob", []byte{0x00, 0x01, 0xff, 0xc3, 0xa9}) // arbitrary binary

	got, err := Unmarshal(Marshal(root))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := got.Uint64("height_upper_limit"); v != 2555000 {
		t.Errorf("height_upper_limit = %d", v)
	}
	if v, _ := got.Uint64("coinbase_percents"); v != 15 {
		t.Errorf("coinbase_percents = %d", v)
	}
	if b, _ := got.Bytes("blob"); string(b) != string([]byte{0x00, 0x01, 0xff, 0xc3, 0xa9}) {
		t.Errorf("blob mismatch: %x", b)
	}
	secs, ok := got.Sections("amounts")
	if !ok || len(secs) != 1 {
		t.Fatalf("amounts: ok=%v len=%d", ok, len(secs))
	}
	if a, _ := secs[0].Uint64("amount"); a != 0 {
		t.Errorf("amount = %d", a)
	}
	v, _ := secs[0].Get("global_offsets")
	arr, ok := v.([]any)
	if !ok || len(arr) != 4 || arr[2].(uint64) != 5928 {
		t.Errorf("global_offsets: %#v", v)
	}
}
