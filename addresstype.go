package zanolib

import "fmt"

// AddressType represents the type of a Zano address, encoded as a varint
// prefix in the base58-encoded address string.
type AddressType uint64

const (
	PublicAddress           AddressType = 0xc5   // Zx — standard public address
	PublicIntegAddress      AddressType = 0x3678 // iZ — integrated address with payment ID
	PublicIntegAddressV2    AddressType = 0x36f8 // iZ — integrated address V2 (with flags)
	PublicAuditAddress      AddressType = 0x98c8 // aZx — auditable public address
	PublicAuditIntegAddress AddressType = 0x8a49 // aiZX — auditable integrated address
)

// String returns a human-readable representation of the address type.
func (a AddressType) String() string {
	switch a {
	case PublicAddress:
		return "Public Address (Zx)"
	case PublicIntegAddress:
		return "Integrated Address (iZ)"
	case PublicIntegAddressV2:
		return "Integrated Address V2 (iZ)"
	case PublicAuditAddress:
		return "Audit Address (aZx)"
	case PublicAuditIntegAddress:
		return "Audit Integrated Address (aiZX)"
	default:
		return fmt.Sprintf("Unknown Address type (%x)", uint64(a))
	}
}

// Auditable returns true if this address type is an auditable address.
func (a AddressType) Auditable() bool {
	return a == PublicAuditAddress || a == PublicAuditIntegAddress
}

// HasFlags returns true if this address type includes a flags byte in its encoding.
func (a AddressType) HasFlags() bool {
	return a == PublicIntegAddressV2 || a == PublicAuditAddress || a == PublicAuditIntegAddress
}
