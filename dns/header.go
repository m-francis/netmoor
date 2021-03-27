package dns

import (
	"encoding/binary"
	"fmt"
)

const (
	HeaderLengthBytes = uint16(12)
)

type Header struct {
	ID      uint16
	QR      uint8
	OpCode  uint8
	AA      uint8
	TC      uint8
	RD      uint8
	RA      uint8
	Z       uint8
	RCode   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

const (
	bytesInID      = 2
	bitsInQR       = 1
	bitsInOpCode   = 4
	bitsInAA       = 1
	bitsInTC       = 1
	bitsInRD       = 1
	bitsInRA       = 1
	bitsInZ        = 3
	bitsInRCode    = 4
	bytesInQDCount = 2
	bytesInANCount = 2
	bytesInNSCount = 2
	bytesInARCount = 2
)

// ToWire transforms the Header into wire format. The result should not be modified.
func (h *Header) ToWire() []byte {
	header := []byte{uint8(h.ID >> 8), uint8(h.ID & 0xff)}

	var oneByte uint8

	oneByte = h.QR & (1<<bitsInQR - 1)
	oneByte <<= bitsInOpCode
	oneByte |= h.OpCode & (1<<bitsInOpCode - 1)
	oneByte <<= bitsInAA
	oneByte |= h.AA & (1<<bitsInAA - 1)
	oneByte <<= bitsInTC
	oneByte |= h.TC & (1<<bitsInTC - 1)
	oneByte <<= bitsInRD
	oneByte |= h.RD & (1<<bitsInRD - 1)
	header = append(header, oneByte)

	oneByte = h.RA & (1<<bitsInRA - 1)
	oneByte <<= bitsInZ
	oneByte |= h.Z & (1<<bitsInZ - 1)
	oneByte <<= bitsInRCode
	oneByte |= h.RCode & (1<<bitsInRCode - 1)
	header = append(header, oneByte)

	twoBytes := make([]byte, 2) // we know they are 16 bit ints

	binary.BigEndian.PutUint16(twoBytes, h.QDCount)
	header = append(header, twoBytes...)

	binary.BigEndian.PutUint16(twoBytes, h.ANCount)
	header = append(header, twoBytes...)

	binary.BigEndian.PutUint16(twoBytes, h.NSCount)
	header = append(header, twoBytes...)

	binary.BigEndian.PutUint16(twoBytes, h.ARCount)
	header = append(header, twoBytes...)

	return header
}

func (h *Header) Log() {
	wire := h.ToWire()
	fmt.Printf("Header in wire format (bytes): %v\n", wire)
	fmt.Printf("Header in wire format (hex): % x\n", wire)
	fmt.Printf("Header in wire format (binary): %08b\n", wire)
}

func NewHeaderFromResponseBytes(rb []byte) *Header {
	h := Header{}

	h.ID = binary.BigEndian.Uint16(rb[:bytesInID])
	offset := bytesInID

	oneByte := rb[offset]
	h.RD = oneByte & (1<<bitsInRD - 1)
	oneByte >>= bitsInRD
	h.TC = oneByte & (1<<bitsInTC - 1)
	oneByte >>= bitsInTC
	h.AA = oneByte & (1<<bitsInAA - 1)
	oneByte >>= bitsInAA
	h.OpCode = oneByte & (1<<bitsInOpCode - 1)
	oneByte >>= bitsInOpCode
	h.QR = oneByte & (1<<bitsInQR - 1)
	offset += 1

	oneByte = rb[offset]
	h.RCode = oneByte & (1<<bitsInRCode - 1)
	oneByte >>= bitsInRCode
	h.Z = oneByte & (1<<bitsInZ - 1)
	oneByte >>= bitsInZ
	h.RA = oneByte & (1<<bitsInRA - 1)
	offset += 1

	h.QDCount = binary.BigEndian.Uint16(rb[offset : offset+bytesInQDCount])
	offset += bytesInQDCount

	h.ANCount = binary.BigEndian.Uint16(rb[offset : offset+bytesInANCount])
	offset += bytesInANCount

	h.NSCount = binary.BigEndian.Uint16(rb[offset : offset+bytesInNSCount])
	offset += bytesInNSCount

	h.ARCount = binary.BigEndian.Uint16(rb[offset : offset+bytesInARCount])
	offset += bytesInARCount

	return &h
}
