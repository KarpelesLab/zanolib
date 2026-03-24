package zanobase

// RefById references a specific output by its source transaction hash and output index.
type RefById struct {
	Hash Value256 // source transaction hash
	N    uint32   // output index in source transaction
}
