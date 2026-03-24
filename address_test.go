package zanolib_test

import (
	"encoding/hex"
	"testing"

	"github.com/ModChain/base58"
	"github.com/KarpelesLab/zanolib"
)

type addressTestVector struct {
	Address   string
	SpendKey  string
	ViewKey   string
	PaymentId string
	Flags     uint8
}

func TestAddressParse(t *testing.T) {
	vectors := []*addressTestVector{
		{
			Address:  "ZxD5aoLDPTdcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp338Se7AxeH",
			SpendKey: "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
			ViewKey:  "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
		},
		{
			Address:   "iZ2Zi6RmTWwcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3iTqEsjvJoco1aLSZXS6T",
			SpendKey:  "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
			ViewKey:   "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
			PaymentId: "87440d0b9acc42f1",
		},
		{
			Address:  "ZxD5aoLDPTdcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3APrDvRoL5C",
			SpendKey: "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
			ViewKey:  "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
			Flags:    0xfe,
		},
		{
			Address:   "iZ4mBxubNfqcaRx4uCpyW4XiLfEXejepAVz8cSY2fwHNEiJNu6NmpBBDLGTJzCsUvn3acCVDVDPMV8yQXdPooAp3iTrG7nU5rRCWmcozLaMoY95sAbo6",
			SpendKey:  "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
			ViewKey:   "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
			PaymentId: "3ba0527bcfb1fa93630d28eed6",
			Flags:     0xfe,
		},
		{
			Address:  "aZxb9Et6FhP9AinRwcPqSqBKjckre7PgoZjK3q5YG2fUKHYWFZMWjB6YAEAdw4yDDUGEQ7CGEgbqhGRKeadGV1jLYcEJMEmqQFn",
			SpendKey: "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
			ViewKey:  "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
			Flags:    0x01,
		},
		{
			Address:   "aiZXDondHWu9AinRwcPqSqBKjckre7PgoZjK3q5YG2fUKHYWFZMWjB6YAEAdw4yDDUGEQ7CGEgbqhGRKeadGV1jLYcEJM9xJH8EbjuRiMJgFmPRATsEV9",
			SpendKey:  "9f5e1fa93630d4b281b18bb67a3db79e9622fc703cc3ad4a453a82e0a36d51fa",
			ViewKey:   "a3f208c8f9ba49bab28eed62b35b0f6be0a297bcd85c2faa1eb1820527bcf7e3",
			PaymentId: "3ba0527bcfb1fa93630d28eed6",
			Flags:     0x01,
		},
	}

	for _, vec := range vectors {
		// test base58 lib too
		b58dec := must(base58.Bitcoin.DecodeChunked(vec.Address))
		b58enc := base58.Bitcoin.EncodeChunked(b58dec)
		if vec.Address != b58enc {
			t.Errorf("invalid base58 encoding %s", b58enc)
		}
		// test zanolib
		addr, err := zanolib.ParseAddress(vec.Address)
		if err != nil {
			t.Errorf("failed to parse address: %s", err)
			continue
		}
		if sk := hex.EncodeToString(addr.SpendKey); sk != vec.SpendKey {
			t.Errorf("invalid spend key: %s != %s", sk, vec.SpendKey)
		}
		if vk := hex.EncodeToString(addr.SpendKey); vk != vec.SpendKey {
			t.Errorf("invalid view key: %s != %s", vk, vec.SpendKey)
		}
		if pi := hex.EncodeToString(addr.PaymentId); pi != vec.PaymentId {
			t.Errorf("invalid payment id: %s != %s", pi, vec.PaymentId)
		}
		if addr.Flags != vec.Flags {
			t.Errorf("invalid flags value: %x != %x", addr.Flags, vec.Flags)
		}
		enc := addr.String()
		if enc != vec.Address {
			t.Errorf("address did not encode back to original value: %s != %s", enc, vec.Address)
		}
		//log.Printf("addr %s", addr.Debug())
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
