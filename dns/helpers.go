package dns

import (
	"encoding/binary"
	"fmt"
)

// DecompressName extracts name out of NAME, QNAME, RD sections of a DNS packet bytes (`rb`).
// The name in the packet may be compressed, in which case it or a subset of it could be
// a pointer to elsewhere in the packet. Offset is the starting index of the name in `rb`.
// It returns the decompressed name and the number of bytes consumed after offset.
func DecompressName(rb []byte, offset uint16) (name string, nb uint16) {
	byteAtOffset := uint8(rb[offset])

	if byteAtOffset == 0 { // root of the name hierarchy
		return "", 1
	}

	if byteAtOffset >= 192 { // compressed; pointer is two bytes
		ptrOffset := binary.BigEndian.Uint16([]byte{
			uint8(byteAtOffset & (1<<6 - 1)), // trailing 6 bits of the first byte
			rb[offset+1],                     // the second byte
		})
		name, _ := DecompressName(rb, ptrOffset)
		return name, 2
	}

	labelLength := byteAtOffset

	labelStartInd := offset + 1
	labelEndInd := labelStartInd + uint16(labelLength)
	label := fmt.Sprintf("%s.", string(rb[labelStartInd:labelEndInd]))

	restOfName, restOfLength := DecompressName(rb, labelEndInd)

	name = label + restOfName
	nb = 1 + uint16(labelLength) + restOfLength

	return
}
