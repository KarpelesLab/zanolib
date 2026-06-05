package zanorpc

import "testing"

func TestBuildDecoyOffsets(t *testing.T) {
	const real = uint64(4511231)
	const ring = 16
	offs, err := buildDecoyOffsets(real, ring)
	if err != nil {
		t.Fatal(err)
	}
	if len(offs) != ring {
		t.Fatalf("got %d offsets, want %d", len(offs), ring)
	}
	seen := map[uint64]bool{}
	hasReal := false
	for i, o := range offs {
		if seen[o] {
			t.Errorf("duplicate offset %d", o)
		}
		seen[o] = true
		if i > 0 && offs[i-1] >= o {
			t.Errorf("offsets not strictly sorted at %d", i)
		}
		if o == real {
			hasReal = true
		} else if o >= real {
			t.Errorf("decoy %d is not older than real %d", o, real)
		}
	}
	if !hasReal {
		t.Error("offsets must include the real global index")
	}

	// not enough older outputs
	if _, err := buildDecoyOffsets(3, 16); err == nil {
		t.Error("expected error when realIndex < ringSize-1")
	}
}
