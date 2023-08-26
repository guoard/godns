package main

import (
	"fmt"
	"os"

	"github.com/guoard/godns/dns"
)

func main() {
	f, err := os.Open("response_packet.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var buffer dns.BytePacketBuffer
	_, err = f.Read(buffer.Buf[:])
	if err != nil {
		panic(err)
	}

	packet, err := dns.DnsPacketFromBuffer(&buffer)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", packet.Header)

	for _, q := range packet.Questions {
		fmt.Printf("%+v\n", q)
	}
	for _, rec := range packet.Answers {
		fmt.Printf("%+v\n", rec)
	}
	for _, rec := range packet.Authorities {
		fmt.Printf("%+v\n", rec)
	}
	for _, rec := range packet.Resources {
		fmt.Printf("%+v\n", rec)
	}
}
