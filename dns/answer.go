package dns

import (
	"encoding/binary"
	"fmt"
)

const (
	bytesInType  = 2
	bytesInClass = 2
	bytesInTTL   = 4
	bytesInRDLen = 2
)

type Answer struct {
	Name         string
	Type         uint16
	Class        uint16
	TTL          uint32
	RDLength     uint16
	RData        []byte
	RDataStr     string
	inWireFormat []byte
}

func (a *Answer) Log() {
	if len(a.inWireFormat) == 0 {
		return
	}
	fmt.Printf("Answer: name=%v type=%v class=%v TTL=%v RDLength=%v RData=%v RDataStr=%v\n", a.Name, a.Type, a.Class, a.TTL, a.RDLength, a.RData, a.RDataStr)
}

func NewAnswersFromResponseBytes(rb []byte, h *Header, offset uint16) (answers []*Answer, endIndex uint16) {
	startIndex := offset
	endIndex = startIndex

	for i := 0; i < int(h.ANCount); i++ {
		a := Answer{}

		name, length := DecompressName(rb, startIndex)

		a.Name = name
		endIndex += length

		a.Type = binary.BigEndian.Uint16(rb[endIndex : endIndex+bytesInType])
		endIndex += bytesInType

		a.Class = binary.BigEndian.Uint16(rb[endIndex : endIndex+bytesInClass])
		endIndex += bytesInClass

		a.TTL = binary.BigEndian.Uint32(rb[endIndex : endIndex+bytesInTTL])
		endIndex += bytesInTTL

		a.RDLength = binary.BigEndian.Uint16(rb[endIndex : endIndex+bytesInRDLen])
		endIndex += bytesInRDLen

		a.RData = rb[endIndex : endIndex+a.RDLength]

		switch a.Type {
		case TypeA:
			a.RDataStr = fmt.Sprintf("%d.%d.%d.%d", uint8(a.RData[0]), uint8(a.RData[1]), uint8(a.RData[2]), uint8(a.RData[3]))
		case TypeCNAME:
			name, _ := DecompressName(rb, endIndex)
			a.RDataStr = name
		}

		endIndex += a.RDLength

		a.inWireFormat = rb[startIndex:endIndex]

		answers = append(answers, &a)

		startIndex = endIndex
	}

	return
}
