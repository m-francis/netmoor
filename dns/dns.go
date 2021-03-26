package dns

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"
)

const (
	WriteTimeout = 2 * time.Second
	ReadTimeout  = 2 * time.Second
)

func Lookup(nameserver string, qns []*Question) *Packet {
	reqPacket := Packet{
		Header: &Header{
			ID:      uint16(rand.Int()),
			RD:      1,
			QDCount: uint16(len(qns)),
		},
		Questions: qns,
	}

	rb := sendAndReceivePacket(nameserver, reqPacket.ToWire())

	return NewPacketFromResponseBytes(rb)
}

func sendAndReceivePacket(nameserver string, reqB []byte) []byte {
	conn, err := net.Dial("udp", fmt.Sprintf("%s:53", nameserver))

	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(WriteTimeout))

	if _, err := conn.Write(reqB); err != nil {
		log.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(ReadTimeout))

	rb := make([]byte, 512)

	for {
		if _, err := conn.Read(rb); err != nil {
			log.Fatal(err)
		}
		return rb
	}
}
