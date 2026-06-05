// Package zanorpc is a minimal JSON-RPC client for a Zano daemon and a deposit
// scanner built on top of it. It fetches raw transaction blobs over JSON-RPC and
// runs zanolib's receive-side scan to detect outputs belonging to a wallet.
//
// The networking lives here, separate from the pure crypto/serialization in the
// root zanolib and zanobase packages.
package zanorpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Client is a JSON-RPC client for a Zano daemon endpoint, e.g.
// "https://rpc.modchain.net/chain/zano/rpc".
type Client struct {
	Endpoint string
	HTTP     *http.Client

	assetMu    sync.RWMutex
	assetCache map[string]*AssetDescriptor
}

// New returns a Client for the given JSON-RPC endpoint using http.DefaultClient.
func New(endpoint string) *Client {
	return &Client{Endpoint: endpoint, HTTP: http.DefaultClient}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("zano rpc error %d: %s", e.Code, e.Message)
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// call performs a single JSON-RPC call and unmarshals the "result" field into out.
func (c *Client) call(ctx context.Context, method string, params, out any) error {
	body, err := json.Marshal(&rpcRequest{JSONRPC: "2.0", ID: 0, Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	httpc := c.HTTP
	if httpc == nil {
		httpc = http.DefaultClient
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MiB cap
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("zano rpc %s: http %d: %s", method, resp.StatusCode, string(data))
	}

	var r rpcResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("zano rpc %s: decode envelope: %w", method, err)
	}
	if r.Error != nil {
		return fmt.Errorf("zano rpc %s: %w", method, r.Error)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(r.Result, out); err != nil {
		return fmt.Errorf("zano rpc %s: decode result: %w", method, err)
	}
	return nil
}

// GetBlockCount returns the current blockchain height (number of blocks).
func (c *Client) GetBlockCount(ctx context.Context) (uint64, error) {
	var res struct {
		Count  uint64 `json:"count"`
		Status string `json:"status"`
	}
	if err := c.call(ctx, "getblockcount", struct{}{}, &res); err != nil {
		return 0, err
	}
	return res.Count, nil
}

// BlockDetails is the subset of a block we need: its height and the list of
// transaction ids it contains.
type BlockDetails struct {
	Height       uint64    `json:"height"`
	Transactions []TxBrief `json:"transactions_details"`
}

// TxBrief identifies a transaction within a block.
type TxBrief struct {
	Id string `json:"id"`
}

// GetBlocksDetails returns details for count blocks starting at height start.
// When ignoreTx is true, transaction details are omitted by the daemon.
func (c *Client) GetBlocksDetails(ctx context.Context, start, count uint64, ignoreTx bool) ([]*BlockDetails, error) {
	params := struct {
		HeightStart        uint64 `json:"height_start"`
		Count              uint64 `json:"count"`
		IgnoreTransactions bool   `json:"ignore_transactions"`
	}{start, count, ignoreTx}
	var res struct {
		Status string          `json:"status"`
		Blocks []*BlockDetails `json:"blocks"`
	}
	if err := c.call(ctx, "get_blocks_details", params, &res); err != nil {
		return nil, err
	}
	return res.Blocks, nil
}

// TxDetails carries the raw transaction blob (decoded from base64) plus the
// per-output global indices needed to later spend received outputs.
type TxDetails struct {
	Id          string
	KeeperBlock uint64
	Blob        []byte
	Outs        []TxOutInfo
}

// TxOutInfo is the daemon's view of a transaction output, in vout order.
type TxOutInfo struct {
	GlobalIndex uint64 `json:"global_index"`
	IsSpent     bool   `json:"is_spent"`
}

type txDetailsRaw struct {
	Id          string      `json:"id"`
	KeeperBlock uint64      `json:"keeper_block"`
	Blob        string      `json:"blob"` // base64
	Outs        []TxOutInfo `json:"outs"`
}

// GetTxDetails fetches a transaction by hash and decodes its raw blob.
func (c *Client) GetTxDetails(ctx context.Context, txHash string) (*TxDetails, error) {
	params := struct {
		TxHash string `json:"tx_hash"`
	}{txHash}
	var res struct {
		Status string       `json:"status"`
		TxInfo txDetailsRaw `json:"tx_info"`
	}
	if err := c.call(ctx, "get_tx_details", params, &res); err != nil {
		return nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(res.TxInfo.Blob)
	if err != nil {
		return nil, fmt.Errorf("get_tx_details %s: decode blob: %w", txHash, err)
	}
	return &TxDetails{
		Id:          res.TxInfo.Id,
		KeeperBlock: res.TxInfo.KeeperBlock,
		Blob:        blob,
		Outs:        res.TxInfo.Outs,
	}, nil
}
