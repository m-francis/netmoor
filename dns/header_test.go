package dns_test

import (
	"bytes"
	"reflect"
	"testing"

	"mfrancis.dev/netmoor/dns"
)

func TestHeader(t *testing.T) {
	testCases := []struct {
		name   string
		header dns.Header
		rb     []byte
	}{
		{
			name:   "every value at its minimum",
			header: dns.Header{},
			rb:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "every value at its maximum",
			header: dns.Header{
				ID:      ^uint16(0),
				QR:      1,
				OpCode:  15,
				AA:      1,
				TC:      1,
				RD:      1,
				RA:      1,
				Z:       7,
				RCode:   15,
				QDCount: ^uint16(0),
				ANCount: ^uint16(0),
				NSCount: ^uint16(0),
				ARCount: ^uint16(0),
			},
			rb: []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		},
		{
			name:   "ID is on",
			header: dns.Header{ID: uint16(9999)},
			rb:     []byte{39, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:   "QR is on",
			header: dns.Header{QR: 1},
			rb:     []byte{0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:   "OpCode is on",
			header: dns.Header{OpCode: 10},
			rb:     []byte{0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:   "AA is on",
			header: dns.Header{AA: 1},
			rb:     []byte{0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:   "TC is on",
			header: dns.Header{TC: 1},
			rb:     []byte{0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:   "RD is on",
			header: dns.Header{RD: 1},
			rb:     []byte{0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:   "RA is on",
			header: dns.Header{RA: 1},
			rb:     []byte{0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:   "Z is on",
			header: dns.Header{Z: 7},
			rb:     []byte{0, 0, 0, 112, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:   "RCode is on",
			header: dns.Header{RCode: 7},
			rb:     []byte{0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:   "QDCount is on",
			header: dns.Header{QDCount: 2},
			rb:     []byte{0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0},
		},
		{
			name:   "ANCount is on",
			header: dns.Header{ANCount: 2},
			rb:     []byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0},
		},
		{
			name:   "NSCount is on",
			header: dns.Header{NSCount: 2},
			rb:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0},
		},
		{
			name:   "ARCount is on",
			header: dns.Header{ARCount: 2},
			rb:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			wire := tc.header.ToWire()
			if bytes.Compare(wire, tc.rb) != 0 {
				t.Fatalf("Header wire format mismatch (expected %v got %v)", tc.rb, wire)
			}
			header := dns.NewHeaderFromResponseBytes(tc.rb)
			if !reflect.DeepEqual(header, &tc.header) {
				t.Fatalf("Headers do not match (expected %v got %v)", tc.header, header)
			}
		})
	}
}
