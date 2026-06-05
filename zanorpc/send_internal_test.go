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

func TestEndpointURLs(t *testing.T) {
	cases := []struct {
		endpoint string
		json     string
		bin      string
	}{
		// empty => modchain gateway layout
		{"", "https://rpc.modchain.net/chain/zano/rpc", "https://rpc.modchain.net/chain/zano/raw/getrandom_outs3.bin"},
		// non-empty => direct daemon (/json_rpc, /<method>.bin)
		{"http://127.0.0.1:11211", "http://127.0.0.1:11211/json_rpc", "http://127.0.0.1:11211/getrandom_outs3.bin"},
		{"http://127.0.0.1:11211/", "http://127.0.0.1:11211/json_rpc", "http://127.0.0.1:11211/getrandom_outs3.bin"},
	}
	for _, tc := range cases {
		c := &Client{Endpoint: tc.endpoint}
		if got := c.jsonRPCURL(); got != tc.json {
			t.Errorf("jsonRPCURL(%q) = %q, want %q", tc.endpoint, got, tc.json)
		}
		if got := c.binURL("getrandom_outs3"); got != tc.bin {
			t.Errorf("binURL(%q) = %q, want %q", tc.endpoint, got, tc.bin)
		}
	}
}
