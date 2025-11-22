package crc

import "hash/crc32"

var table = crc32.MakeTable(crc32.Castagnoli)

// Compute returns the CRC32C checksum for the provided bytes.
func Compute(data []byte) uint32 {
	if len(data) == 0 {
		return 0
	}
	return crc32.Checksum(data, table)
}
