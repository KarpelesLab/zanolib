package zanorpc_test

import (
	"context"
	"testing"
	"time"

	"github.com/KarpelesLab/zanolib/zanorpc"
)

func TestFormatAtomic(t *testing.T) {
	cases := []struct {
		atomic   uint64
		decimals uint8
		want     string
	}{
		{10000, 4, "1.0000"},                // 1 fUSD
		{50000000000, 12, "0.050000000000"}, // 0.05 ZANO
		{1, 4, "0.0001"},
		{0, 4, "0.0000"},
		{0, 0, "0"},
		{12345, 0, "12345"},
		{123, 2, "1.23"},
		{5, 6, "0.000005"},
	}
	for _, c := range cases {
		if got := zanorpc.FormatAtomic(c.atomic, c.decimals); got != c.want {
			t.Errorf("FormatAtomic(%d, %d) = %q, want %q", c.atomic, c.decimals, got, c.want)
		}
	}
}

// TestLiveGetAssetInfo resolves the fUSD asset used in the deposit tests. Opt-in
// via ZANO_RPC_LIVE=1.
func TestLiveGetAssetInfo(t *testing.T) {
	liveOrSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := zanorpc.New(liveEndpoint)
	const fUSD = "86143388bd056a8f0bab669f78f14873fac8e2dd8d57898cdb725a2d5e2e4f8f"
	d, err := c.GetAssetInfo(ctx, fUSD)
	if err != nil {
		t.Fatalf("get_asset_info: %v", err)
	}
	if d.Ticker != "fUSD" {
		t.Errorf("ticker = %q, want fUSD", d.Ticker)
	}
	if d.DecimalPoint != 4 {
		t.Errorf("decimal_point = %d, want 4", d.DecimalPoint)
	}
	if got := d.FormatAmount(10000); got != "1.0000" {
		t.Errorf("FormatAmount(10000) = %q, want 1.0000", got)
	}
	// second call should hit the cache (still correct)
	if d2, err := c.GetAssetInfo(ctx, fUSD); err != nil || d2.Ticker != "fUSD" {
		t.Errorf("cached lookup failed: %v", err)
	}
	t.Logf("%s (%s), %d decimals", d.FullName, d.Ticker, d.DecimalPoint)
}
