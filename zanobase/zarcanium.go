package zanobase

// ZarcaniumTxDataV1 holds transaction fee data stored in the extra field of Zarcanum transactions.
type ZarcaniumTxDataV1 struct {
	Fee uint64 `json:"fee"`
}
