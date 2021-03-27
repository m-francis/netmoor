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
			QType:  dns.TypeA,
			QClass: dns.ClassInternet,
		})
	}

	msg := dns.LookupName(*ns, qns)
	printAnswers(msg)
}

func printAnswers(msg *dns.Message) {
	for _, an := range msg.Answers {
		if an.Type == dns.TypeA {
			fmt.Printf("%s has address %s\n", an.Name, an.RDataStr)
		} else if an.Type == dns.TypeCNAME {
			fmt.Printf("%s is an alias for %s\n", an.Name, an.RDataStr)
		}
	}
}
