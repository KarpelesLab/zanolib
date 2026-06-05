package zanocrypto

import "filippo.io/edwards25519"

// Mul8 returns 8*p, mirroring crypto::point_t::modify_mul8(). On-chain Zarcanum
// outputs store the concealing point, amount commitment and blinded asset id
// pre-multiplied by 1/8; multiplying the stored value by 8 recovers the value
// used in the receiver-side equations. Implemented as three point doublings.
func Mul8(p *edwards25519.Point) *edwards25519.Point {
	r := new(edwards25519.Point).Add(p, p) // 2p
	r.Add(r, r)                            // 4p
	r.Add(r, r)                            // 8p
	return r
}
