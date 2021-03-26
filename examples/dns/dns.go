package main

import (
	"flag"
	"fmt"
	"log"

	"mfrancis.dev/netmoor/dns"
)

type strArr []string

func (n *strArr) String() string {
	return fmt.Sprint(*n)
}

func (n *strArr) Set(name string) error {
	*n = append(*n, name)
	return nil
}

var namesFlag strArr

func main() {
	var ns = flag.String("ns", "8.8.8.8", "DNS Name Server")
	flag.Var(&namesFlag, "name", "name to resolve")

	flag.Parse()

	if len(namesFlag) == 0 {
		log.Fatal("name must be provided")
	}

	var qns []*dns.Question

	for _, name := range namesFlag {
		qns = append(qns, &dns.Question{
			QName:  name,
			QType:  1,
			QClass: 1,
		})
	}

	packet := dns.LookupName(*ns, qns)
	printAnswers(packet)
}

func printAnswers(p *dns.Packet) {
	for _, an := range p.Answers {
		if an.Type == 1 {
			fmt.Printf("%s has address %s\n", an.Name, an.RDataStr)
		} else if an.Type == 5 {
			fmt.Printf("%s is an alias for %s\n", an.Name, an.RDataStr)
		}
	}
}
