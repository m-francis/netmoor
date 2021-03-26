package dns

import (
	"log"
)

const (
	TypeA     = 1
	TypeCNAME = 5
)

type Packet struct {
	Header     *Header
	Questions  []*Question
	Answers    []*Answer
	Authority  []byte
	Additional []byte
}

func (p *Packet) ToWire() []byte {
	var msg []byte
	msg = append(msg, p.Header.ToWire()...)
	for _, qn := range p.Questions {
		msg = append(msg, qn.ToWire()...)
	}
	return msg
}

func (p *Packet) Log() {
	p.Header.Log()
	for _, q := range p.Questions {
		q.Log()
	}
	for _, a := range p.Answers {
		a.Log()
	}
}

func NewPacketFromResponseBytes(rb []byte) *Packet {
	header := NewHeaderFromResponseBytes(rb)
	assertResponseHeader(header)
	questions, offset := NewQuestionFromResponseBytes(rb, header)
	answers, offset := NewAnswersFromResponseBytes(rb, header, offset)
	return &Packet{
		Header:    header,
		Questions: questions,
		Answers:   answers,
	}
}

func assertResponseHeader(h *Header) {
	switch h.RCode {
	case 0:
		return
	case 1:
		log.Fatalf("1(Format Error)")
	case 2:
		log.Fatalf("2(Server Failure)")
	case 3:
		log.Fatalf("3(Name Error)")
	case 4:
		log.Fatalf("4(Not Implemented)")
	case 5:
		log.Fatalf("5(Refused)")
	}
}
