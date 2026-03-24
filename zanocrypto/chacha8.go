package zanocrypto

import (
	"encoding/binary"
	"errors"
	"math/bits"

	"golang.org/x/crypto/sha3"
)

// ChaCha8GenerateKey derives a 32-byte ChaCha8 encryption key from a seed
// by hashing it with Keccak-256. The seed must be at least 32 bytes.
func ChaCha8GenerateKey(seed []byte) ([]byte, error) {
	if len(seed) < 32 {
		return nil, errors.New("Size of hash must be at least that of chacha8_key")
	}
	hash := sha3.NewLegacyKeccak256()
	hash.Write(seed)
	return hash.Sum(nil), nil
}

// ChaCha8 applies the ChaCha8 stream cipher to `in` using the 32-byte key `key`
// and the 8-byte nonce `nonce`. It returns a new slice containing the result.
// This function both encrypts and decrypts (XOR cipher) in the same call.
func ChaCha8(key, nonce, in []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("chacha8: key length must be 32 bytes")
	}
	if len(nonce) != 8 {
		return nil, errors.New("chacha8: nonce (IV) length must be 8 bytes")
	}

	// "expand 32-byte k"
	// In Bernstein's original code, sigma = "expand 32-byte k"
	// It's split into four 32-bit words in little-endian.
	// ASCII: e = 0x65, x = 0x78, p = 0x70, a = 0x61, n = 0x6e, d = 0x64 ...
	var sigma = [4]uint32{
		binary.LittleEndian.Uint32([]byte("expa")),
		binary.LittleEndian.Uint32([]byte("nd 3")),
		binary.LittleEndian.Uint32([]byte("2-by")),
		binary.LittleEndian.Uint32([]byte("te k")),
	}

	// State initialization (16 words).
	// j0..j3  <- constant (sigma)
	// j4..j11 <- key
	// j12..j13 <- block counter (64-bit, here set to 0 initially)
	// j14..j15 <- nonce (64-bit)
	j0 := sigma[0]
	j1 := sigma[1]
	j2 := sigma[2]
	j3 := sigma[3]

	j4 := binary.LittleEndian.Uint32(key[0:4])
	j5 := binary.LittleEndian.Uint32(key[4:8])
	j6 := binary.LittleEndian.Uint32(key[8:12])
	j7 := binary.LittleEndian.Uint32(key[12:16])
	j8 := binary.LittleEndian.Uint32(key[16:20])
	j9 := binary.LittleEndian.Uint32(key[20:24])
	j10 := binary.LittleEndian.Uint32(key[24:28])
	j11 := binary.LittleEndian.Uint32(key[28:32])

	j12 := uint32(0) // low 32 bits of block counter
	j13 := uint32(0) // high 32 bits of block counter

	j14 := binary.LittleEndian.Uint32(nonce[0:4])
	j15 := binary.LittleEndian.Uint32(nonce[4:8])

	out := make([]byte, len(in))

	// Process input in 64-byte blocks
	inputOffset := 0
	outputOffset := 0
	for inputOffset < len(in) {
		// Create a working copy of the state
		x0, x1, x2, x3 := j0, j1, j2, j3
		x4, x5, x6, x7 := j4, j5, j6, j7
		x8, x9, x10, x11 := j8, j9, j10, j11
		x12, x13, x14, x15 := j12, j13, j14, j15

		// 8 rounds total, done as 4 double-rounds:
		// for (i = 8; i > 0; i -= 2) { ... }
		// Each double-round has 8 quarter-round calls.
		for i := 0; i < 4; i++ {
			// Even round
			x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
			x1, x5, x9, x13 = quarterRound(x1, x5, x9, x13)
			x2, x6, x10, x14 = quarterRound(x2, x6, x10, x14)
			x3, x7, x11, x15 = quarterRound(x3, x7, x11, x15)
			// Odd round
			x0, x5, x10, x15 = quarterRound(x0, x5, x10, x15)
			x1, x6, x11, x12 = quarterRound(x1, x6, x11, x12)
			x2, x7, x8, x13 = quarterRound(x2, x7, x8, x13)
			x3, x4, x9, x14 = quarterRound(x3, x4, x9, x14)
		}

		// Add the original state
		x0 += j0
		x1 += j1
		x2 += j2
		x3 += j3
		x4 += j4
		x5 += j5
		x6 += j6
		x7 += j7
		x8 += j8
		x9 += j9
		x10 += j10
		x11 += j11
		x12 += j12
		x13 += j13
		x14 += j14
		x15 += j15

		// Construct the 64-byte keystream block
		keystreamBlock := make([]byte, 64)
		binary.LittleEndian.PutUint32(keystreamBlock[0:4], x0)
		binary.LittleEndian.PutUint32(keystreamBlock[4:8], x1)
		binary.LittleEndian.PutUint32(keystreamBlock[8:12], x2)
		binary.LittleEndian.PutUint32(keystreamBlock[12:16], x3)
		binary.LittleEndian.PutUint32(keystreamBlock[16:20], x4)
		binary.LittleEndian.PutUint32(keystreamBlock[20:24], x5)
		binary.LittleEndian.PutUint32(keystreamBlock[24:28], x6)
		binary.LittleEndian.PutUint32(keystreamBlock[28:32], x7)
		binary.LittleEndian.PutUint32(keystreamBlock[32:36], x8)
		binary.LittleEndian.PutUint32(keystreamBlock[36:40], x9)
		binary.LittleEndian.PutUint32(keystreamBlock[40:44], x10)
		binary.LittleEndian.PutUint32(keystreamBlock[44:48], x11)
		binary.LittleEndian.PutUint32(keystreamBlock[48:52], x12)
		binary.LittleEndian.PutUint32(keystreamBlock[52:56], x13)
		binary.LittleEndian.PutUint32(keystreamBlock[56:60], x14)
		binary.LittleEndian.PutUint32(keystreamBlock[60:64], x15)

		// XOR the keystream with the input block (or partial block)
		blockSize := 64
		if (len(in) - inputOffset) < blockSize {
			blockSize = len(in) - inputOffset
		}
		for i := 0; i < blockSize; i++ {
			out[outputOffset+i] = in[inputOffset+i] ^ keystreamBlock[i]
		}

		// Advance counters
		j12++
		if j12 == 0 {
			j13++
			// note: "stopping at 2^70 bytes per nonce is user's responsibility"
		}

		inputOffset += blockSize
		outputOffset += blockSize
	}

	return out, nil
}

// quarterRound implements the ChaCha quarter-round operation:
//
//	a += b; d ^= a; d <<<= 16
//	c += d; b ^= c; b <<<= 12
//	a += b; d ^= a; d <<<= 8
//	c += d; b ^= c; b <<<= 7
func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)

	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)

	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)

	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)

	return a, b, c, d
}
