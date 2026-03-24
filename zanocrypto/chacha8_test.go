package zanocrypto_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/zanolib/zanocrypto"
)

func TestChaCha8GenerateKey(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	key, err := zanocrypto.ChaCha8GenerateKey(seed)
	if err != nil {
		t.Fatalf("ChaCha8GenerateKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	// Deterministic: same seed should produce the same key
	key2, err := zanocrypto.ChaCha8GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, key2) {
		t.Error("ChaCha8GenerateKey not deterministic")
	}
}

func TestChaCha8GenerateKeyTooShort(t *testing.T) {
	_, err := zanocrypto.ChaCha8GenerateKey(make([]byte, 16))
	if err == nil {
		t.Error("expected error for short seed")
	}
}

func TestChaCha8EncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 8)

	plaintext := []byte("Hello, Zano! This is a test of ChaCha8 encryption.")

	encrypted, err := zanocrypto.ChaCha8(key, nonce, plaintext)
	if err != nil {
		t.Fatalf("ChaCha8 encrypt failed: %v", err)
	}

	// Ciphertext should differ from plaintext
	if bytes.Equal(encrypted, plaintext) {
		t.Error("encrypted text is same as plaintext")
	}

	// Decrypt (XOR cipher: encrypt again = decrypt)
	decrypted, err := zanocrypto.ChaCha8(key, nonce, encrypted)
	if err != nil {
		t.Fatalf("ChaCha8 decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted text doesn't match original: %q vs %q", decrypted, plaintext)
	}
}

func TestChaCha8EmptyInput(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 8)

	result, err := zanocrypto.ChaCha8(key, nonce, []byte{})
	if err != nil {
		t.Fatalf("ChaCha8 failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(result))
	}
}

func TestChaCha8MultiBlock(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 8)

	// Test with data larger than one block (64 bytes)
	plaintext := make([]byte, 200)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, err := zanocrypto.ChaCha8(key, nonce, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := zanocrypto.ChaCha8(key, nonce, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("multi-block round-trip failed")
	}
}

func TestChaCha8InvalidKeyLength(t *testing.T) {
	_, err := zanocrypto.ChaCha8(make([]byte, 16), make([]byte, 8), []byte("test"))
	if err == nil {
		t.Error("expected error for 16-byte key")
	}
}

func TestChaCha8InvalidNonceLength(t *testing.T) {
	_, err := zanocrypto.ChaCha8(make([]byte, 32), make([]byte, 12), []byte("test"))
	if err == nil {
		t.Error("expected error for 12-byte nonce")
	}
}

func TestChaCha8DifferentKeys(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1
	nonce := make([]byte, 8)
	plaintext := []byte("test data for different keys")

	enc1, _ := zanocrypto.ChaCha8(key1, nonce, plaintext)
	enc2, _ := zanocrypto.ChaCha8(key2, nonce, plaintext)

	if bytes.Equal(enc1, enc2) {
		t.Error("different keys produced same ciphertext")
	}
}

func TestChaCha8KnownVector(t *testing.T) {
	// Test that ChaCha8 with a known key/nonce produces consistent output
	key, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	nonce := make([]byte, 8)
	plaintext := make([]byte, 64) // all zeros

	result, err := zanocrypto.ChaCha8(key, nonce, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// The keystream for all-zero key and nonce should be deterministic
	// Verify it's non-zero (the keystream shouldn't be all zeros)
	allZero := true
	for _, b := range result {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("ChaCha8 produced all zeros with zero key (keystream is zero)")
	}

	// Verify determinism
	result2, _ := zanocrypto.ChaCha8(key, nonce, plaintext)
	if !bytes.Equal(result, result2) {
		t.Error("ChaCha8 not deterministic")
	}
}
