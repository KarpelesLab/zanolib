package zanobase

// KeyImageIndex pairs an output index with its corresponding key image.
type KeyImageIndex struct {
	OutIndex uint64
	Image    Value256 // ec_point
}
