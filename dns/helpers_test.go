package dns_test

import (
	"testing"

	"mfrancis.dev/netmoor/dns"
)

func TestDecompressName(t *testing.T) {
	tc := []struct {
		desc   string
		rb     []byte
		offset uint16
		name   string
		length uint16
	}{
		{
			desc:   "one label, uncompressed",
			rb:     []byte{3, 119, 119, 119, 0},
			offset: 0,
			name:   "www.",
			length: 5,
		},
		{
			desc:   "full name, uncompressed",
			rb:     []byte{3, 119, 119, 119, 8, 109, 102, 114, 97, 110, 99, 105, 115, 3, 100, 101, 118, 0},
			offset: 0,
			name:   "www.mfrancis.dev.",
			length: 18,
		},
		{
			desc:   "full name is a pointer",
			rb:     []byte{3, 119, 119, 119, 8, 109, 102, 114, 97, 110, 99, 105, 115, 3, 100, 101, 118, 0, 192, 0},
			offset: 18,
			name:   "www.mfrancis.dev.",
			length: 2,
		},
		{
			desc:   "subset of name is a pointer",
			rb:     []byte{8, 109, 102, 114, 97, 110, 99, 105, 115, 3, 100, 101, 118, 0, 3, 119, 119, 119, 192, 0},
			offset: 14,
			name:   "www.mfrancis.dev.",
			length: 6,
		},
	}

	for _, tc := range tc {
		t.Run(tc.desc, func(t *testing.T) {
			name, length := dns.DecompressName(tc.rb, tc.offset)
			if name != tc.name {
				t.Fatalf("name does not match (expected %s was %s)", tc.name, name)
			}
			if length != tc.length {
				t.Fatalf("length does not match (expected %d was %d)", tc.length, length)
			}
		})
	}
}
