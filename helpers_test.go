package zanolib_test

// fakeRnd is a deterministic io.Reader (all 0x42 bytes) used by tests that need
// reproducible signatures/proofs.
type fakeRnd struct{}

func (f *fakeRnd) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0x42
	}
	return len(b), nil
}
