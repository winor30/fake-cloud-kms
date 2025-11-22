package crc

import (
	"hash/crc32"
	"testing"
)

func TestCompute(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
		want uint32
	}{
		{name: "empty returns zero", in: nil, want: 0},
		{name: "computes castagnoli", in: []byte("fake-cloud-kms"), want: crc32.Checksum([]byte("fake-cloud-kms"), crc32.MakeTable(crc32.Castagnoli))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Compute(tc.in); got != tc.want {
				t.Fatalf("Compute(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
