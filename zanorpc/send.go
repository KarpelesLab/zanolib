package zanorpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strings"

	"github.com/KarpelesLab/zanolib/epee"
	"github.com/KarpelesLab/zanolib/zanobase"
)

// OutEntry is a single ring-member output returned by getrandom_outs3: its
// global index plus the public output data needed to use it as a decoy. The
// point fields are stored pre-multiplied by 1/8 (as on-chain).
type OutEntry struct {
	GlobalIndex      uint64
	StealthAddress   zanobase.Value256
	ConcealingPoint  zanobase.Value256
	AmountCommitment zanobase.Value256
	BlindedAssetId   zanobase.Value256
	Flags            uint64
}

// outEntrySize is the packed size of currency::out_entry (#pragma pack(1)):
// uint64 + 4*public_key + uint64 = 8 + 128 + 8.
const outEntrySize = 144

// GetRingForOutput fetches a ring (real output + decoys) for a ZC output via
// getrandom_outs3 on the daemon's binary (.bin) endpoint — the method Zano's
// regular send path uses, with client-chosen decoy global offsets. We sample
// ringSize-1 distinct random indices strictly below realGlobalIndex (so every
// decoy is an older, valid ZC output) and include realGlobalIndex itself, so the
// daemon returns the real output's own public data alongside the decoys. The
// returned entries include the real output; the caller locates it by GlobalIndex.
//
// The .bin endpoint exchanges epee portable-storage binary (not JSON), so the
// out_entry POD blob comes back as exact bytes — no binary-in-JSON decoding.
func (c *Client) GetRingForOutput(ctx context.Context, realGlobalIndex uint64, ringSize int) ([]OutEntry, error) {
	offsets, err := buildDecoyOffsets(realGlobalIndex, ringSize)
	if err != nil {
		return nil, err
	}

	dist := epee.NewSection()
	dist.Set("amount", uint64(0)) // 0 => ZC (post-zarcanum) zone
	dist.Set("global_offsets", offsets)
	req := epee.NewSection()
	req.Set("amounts", []*epee.Section{dist})
	req.Set("height_upper_limit", uint64(0))
	req.Set("use_forced_mix_outs", false)
	req.Set("coinbase_percents", uint64(0))

	respBytes, err := c.postBin(ctx, "getrandom_outs3", epee.Marshal(req))
	if err != nil {
		return nil, fmt.Errorf("getrandom_outs3.bin: %w", err)
	}
	resp, err := epee.Unmarshal(respBytes)
	if err != nil {
		return nil, fmt.Errorf("getrandom_outs3.bin: decode: %w", err)
	}
	if st, ok := resp.Bytes("status"); ok && string(st) != "OK" && string(st) != "" {
		return nil, fmt.Errorf("getrandom_outs3.bin: status %q", string(st))
	}

	batches, ok := resp.Sections("outs")
	if !ok || len(batches) == 0 {
		return nil, fmt.Errorf("getrandom_outs3.bin: empty outs")
	}
	blob, ok := batches[0].Bytes("outs")
	if !ok {
		return nil, fmt.Errorf("getrandom_outs3.bin: missing out_entry blob")
	}
	if len(blob)%outEntrySize != 0 {
		return nil, fmt.Errorf("getrandom_outs3.bin: blob length %d not a multiple of %d", len(blob), outEntrySize)
	}

	n := len(blob) / outEntrySize
	res := make([]OutEntry, n)
	for i := 0; i < n; i++ {
		rec := blob[i*outEntrySize : (i+1)*outEntrySize]
		res[i].GlobalIndex = binary.LittleEndian.Uint64(rec[0:8])
		copy(res[i].StealthAddress[:], rec[8:40])
		copy(res[i].ConcealingPoint[:], rec[40:72])
		copy(res[i].AmountCommitment[:], rec[72:104])
		copy(res[i].BlindedAssetId[:], rec[104:136])
		res[i].Flags = binary.LittleEndian.Uint64(rec[136:144])
	}
	return res, nil
}

// SendRawTx broadcasts a fully-serialized transaction via sendrawtransaction
// (a JSON-RPC method). Returns the daemon status string ("OK" on success).
func (c *Client) SendRawTx(ctx context.Context, raw []byte) (string, error) {
	params := struct {
		TxAsBase64 string `json:"tx_as_base64"`
	}{base64.StdEncoding.EncodeToString(raw)}
	var res struct {
		Status string `json:"status"`
	}
	if err := c.call(ctx, "sendrawtransaction", params, &res); err != nil {
		return "", err
	}
	return res.Status, nil
}

// binURL derives the daemon's binary endpoint for a method from the JSON-RPC
// Endpoint, e.g. ".../chain/zano/rpc" -> ".../chain/zano/raw/<method>.bin".
func (c *Client) binURL(method string) string {
	base := strings.TrimSuffix(c.Endpoint, "/rpc")
	return base + "/raw/" + method + ".bin"
}

// postBin posts an epee-serialized request body to a .bin endpoint and returns
// the raw response bytes.
func (c *Client) postBin(ctx context.Context, method string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.binURL(method), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	httpc := c.HTTP
	if httpc == nil {
		httpc = http.DefaultClient
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

// buildDecoyOffsets returns `ringSize` sorted, unique global indices to request:
// realGlobalIndex plus ringSize-1 distinct random indices in [0, realGlobalIndex)
// (all older than the real output, hence valid ring members of sufficient age).
func buildDecoyOffsets(realGlobalIndex uint64, ringSize int) ([]uint64, error) {
	if ringSize < 1 {
		return nil, fmt.Errorf("ringSize must be >= 1")
	}
	if uint64(ringSize-1) > realGlobalIndex {
		return nil, fmt.Errorf("not enough older outputs (%d) for %d decoys", realGlobalIndex, ringSize-1)
	}
	set := map[uint64]struct{}{realGlobalIndex: {}}
	for len(set) < ringSize {
		n, err := randUint64Below(realGlobalIndex)
		if err != nil {
			return nil, err
		}
		set[n] = struct{}{}
	}
	out := make([]uint64, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// randUint64Below returns a uniform random value in [0, n) using crypto/rand.
func randUint64Below(n uint64) (uint64, error) {
	if n == 0 {
		return 0, fmt.Errorf("randUint64Below: n must be > 0")
	}
	v, err := rand.Int(rand.Reader, new(big.Int).SetUint64(n))
	if err != nil {
		return 0, err
	}
	return v.Uint64(), nil
}
