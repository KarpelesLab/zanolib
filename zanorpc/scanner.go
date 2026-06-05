package zanorpc

import (
	"bytes"
	"context"
	"fmt"

	"github.com/KarpelesLab/zanolib"
	"github.com/KarpelesLab/zanolib/zanobase"
)

// Deposit is a single received output discovered by the Scanner, with enough
// context (height, tx id, payment id, global index) to credit a user and to
// later build a spendable source.
type Deposit struct {
	Height      uint64
	TxId        string
	GlobalIndex uint64                  // chain-assigned global output index (0 if unavailable)
	PaymentId   []byte                  // integrated-address payment id, if the tx carried one
	Out         *zanolib.ReceivedOutput // decoded amount, asset, blinding masks, stealth address
}

// Scanner walks confirmed blocks from a Zano daemon and reports outputs that
// belong to Wallet. The caller is responsible for persisting the last scanned
// height (and re-scanning a small tail on restart to absorb reorgs).
type Scanner struct {
	Wallet *zanolib.Wallet
	RPC    *Client
	// BatchSize is the number of blocks requested per get_blocks_details call.
	// Zero uses DefaultBatchSize.
	BatchSize uint64
}

// DefaultBatchSize is the default number of blocks fetched per RPC round-trip.
const DefaultBatchSize = 100

// NewScanner builds a Scanner for the given wallet and endpoint.
func NewScanner(w *zanolib.Wallet, endpoint string) *Scanner {
	return &Scanner{Wallet: w, RPC: New(endpoint)}
}

// ScanRange scans blocks in the inclusive height range [from, to], invoking fn
// for every deposit found. It returns the height of the last fully scanned block
// (so the caller can persist progress); on error it returns the last height
// completed before the failure. If fn returns an error, scanning stops and that
// error is returned along with the last fully completed height.
func (s *Scanner) ScanRange(ctx context.Context, from, to uint64, fn func(Deposit) error) (uint64, error) {
	if to < from {
		return from - 1, nil
	}
	batch := s.BatchSize
	if batch == 0 {
		batch = DefaultBatchSize
	}

	lastDone := from - 1
	for h := from; h <= to; {
		count := batch
		if h+count-1 > to {
			count = to - h + 1
		}
		blocks, err := s.RPC.GetBlocksDetails(ctx, h, count, false)
		if err != nil {
			return lastDone, err
		}

		for _, blk := range blocks {
			if err := s.scanBlock(ctx, blk, fn); err != nil {
				return lastDone, err
			}
			lastDone = blk.Height
		}

		// Advance even if the daemon returned fewer blocks than requested
		// (e.g. near the tip): never loop forever.
		got := uint64(len(blocks))
		if got == 0 {
			break
		}
		h += got
	}
	return lastDone, nil
}

func (s *Scanner) scanBlock(ctx context.Context, blk *BlockDetails, fn func(Deposit) error) error {
	for _, txb := range blk.Transactions {
		td, err := s.RPC.GetTxDetails(ctx, txb.Id)
		if err != nil {
			return fmt.Errorf("block %d tx %s: %w", blk.Height, txb.Id, err)
		}
		// Parse only the prefix + attachment (enough for output detection and
		// payment-id recovery); this skips signatures/proofs such as the PoS
		// zarcanum_sig that the scanner does not need.
		tx, err := zanobase.DeserializeForScan(bytes.NewReader(td.Blob))
		if err != nil {
			return fmt.Errorf("block %d tx %s: parse blob: %w", blk.Height, txb.Id, err)
		}
		res, err := s.Wallet.ScanTx(tx)
		if err != nil {
			return fmt.Errorf("block %d tx %s: scan: %w", blk.Height, txb.Id, err)
		}
		for _, out := range res.Outputs {
			dep := Deposit{
				Height:    blk.Height,
				TxId:      txb.Id,
				PaymentId: res.PaymentId,
				Out:       out,
			}
			if out.OutputIndex < len(td.Outs) {
				dep.GlobalIndex = td.Outs[out.OutputIndex].GlobalIndex
			}
			if err := fn(dep); err != nil {
				return err
			}
		}
	}
	return nil
}
