package zanobase

// AccountPublicAddr holds the public spend key, view key, and flags for a Zano account address.
type AccountPublicAddr struct {
	SpendKey Value256
	ViewKey  Value256
	Flags    uint8
}
