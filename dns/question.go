package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	bytesInQType  = 2
	bytesInQClass = 2
)

type Question struct {
	QName        string
	QType        uint16
	QClass       uint16
	inWireFormat []byte
}

func (q *Question) ToWire() []byte {
	if len(q.inWireFormat) != 0 {
		return q.inWireFormat
	}

	var question []byte

	if !strings.HasSuffix(q.QName, ".") {
		q.QName += "."
	}

	for _, label := range strings.Split(q.QName, ".") {
		question = append(question, byte(uint8(len(label))))
		question = append(question, []byte(label)...)
	}

	twoBytes := make([]byte, 2) // we know they are 16 bit ints

	binary.BigEndian.PutUint16(twoBytes, q.QType)
	question = append(question, twoBytes...)

	binary.BigEndian.PutUint16(twoBytes, q.QClass)
	question = append(question, twoBytes...)

	q.inWireFormat = question

	return question
}

func (q *Question) Log() {
	if len(q.inWireFormat) == 0 {
		q.ToWire()
	}
	fmt.Printf("Question in wire format (bytes): %v\n", q.ToWire())
	fmt.Printf("Question in wire format (hex): % x\n", q.ToWire())
	fmt.Printf("Question in wire format (binary): %08b\n", q.ToWire())
}

func NewQuestionFromResponseBytes(rb []byte, h *Header) (questions []*Question, endIndex uint16) {
	startIndex := uint16(len(h.inWireFormat))
	endIndex = startIndex

	for i := 0; i < int(h.QDCount); i++ {
		q := Question{}

		qname, length := DecompressName(rb, startIndex)

		q.QName = qname
		endIndex += length

		q.QType = binary.BigEndian.Uint16(rb[endIndex : endIndex+bytesInQType])
		endIndex += bytesInQType

		q.QClass = binary.BigEndian.Uint16(rb[endIndex : endIndex+bytesInQClass])
		endIndex += bytesInQClass

		q.inWireFormat = rb[startIndex:endIndex]

		questions = append(questions, &q)

		startIndex = endIndex
	}

	return
}
