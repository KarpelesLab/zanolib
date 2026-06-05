package zanocrypto

import (
	"math/bits"
)

func ceilLog2(x int) int {
	// By definition, ceil(log2(1)) = 0
	if x <= 1 {
		return 0
	}
	// bits.Len(uint(x - 1)) gives the number of bits needed
	// to represent (x-1), which is effectively ceil(log2(x)).
	return bits.Len(uint(x - 1))
}

// intPow is a integer version of pow()
func intPow(base, exp int) int {
	result := 1
	for {
		if exp&1 == 1 {
			result *= base
		}
		exp >>= 1
		if exp == 0 {
			break
		}
		base *= base
	}

	return result
}

// ceilLogN returns the smallest integer m such that ringSize <= n^m,
// mirroring crypto::constexpr_ceil_log_n(v, n) from crypto-sugar.h.
// (Note: this is log base n of ringSize, not the m^n the name might suggest.)
func ceilLogN(ringSize, n int) int {
	if ringSize <= 1 || n <= 1 {
		return 0
	}
	m := 0
	for p := 1; p < ringSize; p *= n {
		m++
	}
	return m
}
