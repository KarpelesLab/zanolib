package zanorpc

import (
	"context"
	"strconv"
	"strings"
)

// AssetDescriptor describes a Zano confidential asset, as returned by the
// daemon's get_asset_info. The native coin is not a registered asset and has no
// descriptor; see ReceivedOutput.IsNative.
type AssetDescriptor struct {
	Ticker         string `json:"ticker"`
	FullName       string `json:"full_name"`
	DecimalPoint   uint8  `json:"decimal_point"`
	CurrentSupply  uint64 `json:"current_supply"`
	TotalMaxSupply uint64 `json:"total_max_supply"`
	HiddenSupply   bool   `json:"hidden_supply"`
	Owner          string `json:"owner"`
	OwnerEthPubKey string `json:"owner_eth_pub_key"`
	MetaInfo       string `json:"meta_info"`
}

// FormatAmount renders an atomic amount as a decimal string using this asset's
// decimal_point (e.g. 10000 with DecimalPoint 4 -> "1.0000").
func (d *AssetDescriptor) FormatAmount(atomic uint64) string {
	return FormatAtomic(atomic, d.DecimalPoint)
}

// FormatAtomic renders an atomic amount with the given number of decimals.
func FormatAtomic(atomic uint64, decimals uint8) string {
	s := strconv.FormatUint(atomic, 10)
	if decimals == 0 {
		return s
	}
	d := int(decimals)
	if len(s) <= d {
		s = strings.Repeat("0", d-len(s)+1) + s
	}
	return s[:len(s)-d] + "." + s[len(s)-d:]
}

// GetAssetInfo looks up the descriptor for a confidential asset by its hex id
// (e.g. ReceivedOutput.AssetId.String()). Results are cached per Client, since
// asset descriptors rarely change. Returns an error for unknown asset ids.
func (c *Client) GetAssetInfo(ctx context.Context, assetIdHex string) (*AssetDescriptor, error) {
	if c.assetCache != nil {
		c.assetMu.RLock()
		d, ok := c.assetCache[assetIdHex]
		c.assetMu.RUnlock()
		if ok {
			return d, nil
		}
	}

	params := struct {
		AssetId string `json:"asset_id"`
	}{assetIdHex}
	var res struct {
		Status          string          `json:"status"`
		AssetDescriptor AssetDescriptor `json:"asset_descriptor"`
	}
	if err := c.call(ctx, "get_asset_info", params, &res); err != nil {
		return nil, err
	}
	d := &res.AssetDescriptor

	c.assetMu.Lock()
	if c.assetCache == nil {
		c.assetCache = make(map[string]*AssetDescriptor)
	}
	c.assetCache[assetIdHex] = d
	c.assetMu.Unlock()
	return d, nil
}
