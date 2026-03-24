package zanolib

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/ModChain/base58"
	"github.com/KarpelesLab/zanolib/zanobase"
	"golang.org/x/crypto/sha3"
)

type Address struct {
	Type      AddressType
	Flags     uint8
	SpendKey  []byte
	ViewKey   []byte
	PaymentId []byte
}

// ParseAddress will parse a zano address and return and Address object containing the address
func ParseAddress(addr string) (*Address, error) {
	payload, err := base58.Bitcoin.DecodeChunked(addr)
	if err != nil {
		return nil, err
	}
	if len(payload) < 64+4 {
		return nil, errors.New("address is too short")
	}
	ckSum := payload[len(payload)-4:]
	payload = payload[:len(payload)-4]

	check := hsum(sha3.NewLegacyKeccak256, payload)
	if !bytes.Equal(check[:4], ckSum) {
		return nil, errors.New("invalid checksum in address")
	}

	// address starts with a varint
	payload, typ, err := zanobase.VarintTakeUint64(payload)
	if err != nil {
		return nil, err
	}

	if len(payload) < 64 {
		return nil, errors.New("address is too short")
	}

	res := &Address{
		Type:      AddressType(typ),
		SpendKey:  payload[:32],
		ViewKey:   payload[32:64],
		PaymentId: payload[64:],
	}
	if res.Type.HasFlags() {
		// payment id starts with flag value
		if len(res.PaymentId) < 1 {
			return nil, errors.New("address is too short while reading flags")
		}
		res.Flags = res.PaymentId[0]
		res.PaymentId = res.PaymentId[1:]
	} else if res.Type == PublicAddress && len(res.PaymentId) > 0 {
		res.Flags = res.PaymentId[0]
		res.PaymentId = res.PaymentId[1:]
	}

	return res, nil
}

func (addr *Address) Debug() string {
	return fmt.Sprintf("type=%s spendKey=%x viewKey=%x flags=%x paymentId=%x", addr.Type, addr.SpendKey, addr.ViewKey, addr.Flags, addr.PaymentId)
}

// String returns the address encoded as a standard Zano address
func (addr *Address) String() string {
	// transform address back to a string
	buf := slices.Concat(zanobase.VarintAppendUint64(nil, uint64(addr.Type)), addr.SpendKey, addr.ViewKey)
	switch addr.Type {
	case PublicAddress:
		// because PublicAddress has no payment id, presence of extra data means flags
		if addr.Flags != 0 {
			buf = append(buf, addr.Flags)
		}
	default:
		if addr.Type.HasFlags() {
			buf = append(buf, addr.Flags)
		}
		buf = append(buf, addr.PaymentId...)
	}

	// hash
	buf = append(buf, hsum(sha3.NewLegacyKeccak256, buf)[:4]...)
	// encode
	return base58.Bitcoin.EncodeChunked(buf)
}

// SetPaymentId sets the payment ID for the given address, and updates the
// address type accordingly.
func (addr *Address) SetPaymentId(paymentId []byte) error {
	if len(paymentId) > 128 {
		return errors.New("payment id is too long")
	}

	if len(paymentId) == 0 {
		// remove payment id
		addr.PaymentId = nil
		switch addr.Type {
		case PublicIntegAddress, PublicIntegAddressV2:
			addr.Type = PublicAddress
		case PublicAuditIntegAddress:
			addr.Type = PublicAuditAddress
		}
		return nil
	}

	addr.PaymentId = paymentId

	switch addr.Type {
	case PublicAddress:
		if addr.Flags != 0 {
			addr.Type = PublicIntegAddressV2
		} else {
			addr.Type = PublicIntegAddress
		}
	case PublicAuditAddress:
		addr.Type = PublicAuditIntegAddress
	}
	return nil
}
