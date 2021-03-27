package dns

import (
	"log"
)

const (
	TypeA         = 1
	TypeCNAME     = 5
	ClassInternet = 1
)

type Message struct {
	Header     *Header
	Questions  []*Question
	Answers    []*Answer
	Authority  []byte
	Additional []byte
}

func (m *Message) ToWire() []byte {
	var msg []byte

	msg = append(msg, m.Header.ToWire()...)

	for _, qn := range m.Questions {
		msg = append(msg, qn.ToWire()...)
	}

	return msg
}

func (m *Message) Log() {
	m.Header.Log()
	for _, q := range m.Questions {
		q.Log()
	}
	for _, a := range m.Answers {
		a.Log()
	}
}

func NewMessageFromResponseBytes(rb []byte) *Message {
	header := NewHeaderFromResponseBytes(rb)
	assertResponseHeader(header)
	questions, offset := NewQuestionFromResponseBytes(rb, header)
	answers, offset := NewAnswersFromResponseBytes(rb, header, offset)
	return &Message{
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
