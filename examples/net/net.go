package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	names, err := net.LookupAddr("185.199.111.153")

	if err != nil {
		log.Println(err)
	}

	fmt.Printf("addr of %v is %+v\n", "185.199.111.153", names)

	cname, err := net.LookupCNAME("gh-pages.mfrancis.dev")

	if err != nil {
		log.Println(err)
	}

	fmt.Printf("cname of %v is %v\n", "gh-pages.mfrancis.dev", cname)

	addrs, err := net.LookupHost("m-francis.github.io")

	if err != nil {
		log.Println(err)
	}

	fmt.Printf("host of %v is %v\n", "m-francis.github.io", addrs)

	// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
	port, err := net.LookupPort("tcp", "domain") // 53

	if err != nil {
		log.Println(err)
	}

	fmt.Printf("port: %v\n", port)

	record, err := net.LookupTXT("mfrancis.dev")

	if err != nil {
		log.Println(err)
	}

	fmt.Printf("txt of %v is %+v\n", "mfrancis.dev", record)

	Lookup("8.8.8.8", "www.mfrancis.dev.")
}

func Lookup(nameserver, name string) {
	n, err := dnsmessage.NewName(name)

	if err != nil {
		log.Fatal(err)
	}

	qtype := dnsmessage.TypeA

	q := dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}

	id := uint16(rand.Int()) ^ uint16(time.Now().UnixNano())

	b := dnsmessage.NewBuilder(
		make([]byte, 2, 514),
		dnsmessage.Header{ID: id, RecursionDesired: true},
	)
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		log.Fatal(err)
	}

	if err := b.Question(q); err != nil {
		log.Fatal(err)
	}

	tcpReq, err := b.Finish()

	udpReq := tcpReq[2:]

	conn, err := net.Dial("udp", fmt.Sprintf("%s:53", nameserver))

	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	if _, err := conn.Write(udpReq); err != nil {
		log.Fatal(err)
	}

	var p dnsmessage.Parser

	rb := make([]byte, 512)

	for {
		n, err := conn.Read(rb)

		if err != nil {
			log.Fatal(err)
		}

		_, err = p.Start(rb[:n])

		if err != nil {
			continue
		}

		_, err = p.Question()

		if err != nil {
			continue
		}

		break
	}

	if err != nil {
		log.Fatal(err)
	}

	if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
		log.Fatal(err)
	}

	a, err := p.AllAnswers()

	if err != nil {
		log.Fatal(err)
	}

	for _, an := range a {
		switch an.Header.Type {
		case dnsmessage.TypeA:
			fmt.Printf("%v has address %v\n", an.Header.Name, an.Body.GoString())
		case dnsmessage.TypeCNAME:
			fmt.Printf("%v is an alias for %v\n", an.Header.Name, an.Body.GoString())
		}
	}
}
