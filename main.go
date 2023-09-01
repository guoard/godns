package main

import (
	"fmt"
	"os"
	"net"

	"github.com/guoard/godns/dns"
)

func main() {
	// Perform an A query for google.com
	qname := "google.com"
	qtype := dns.A

	// Using Google's public DNS server
	server := "8.8.8.8:53"

	// Bind a UDP socket to an arbitrary port
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 43210})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error binding UDP socket:", err)
		os.Exit(1)
	}
	defer socket.Close()

	// Build our query packet. It's important that we remember to set the
	// `recursionDesired` flag. As noted earlier, the packet id is arbitrary.
	packet := dns.DnsPacket{
		Header: dns.DnsHeader{
			Id:               6666,
			Questions:        1,
			RecursionDesired: true,
		},
		Questions: []dns.DnsQuestion{
			{
				Name: qname,
				Qtype: qtype,
			},
		},
	}

	// Use the write method to write the packet to a buffer
	var reqBuffer dns.BytePacketBuffer
	packet.Write(&reqBuffer)

	// Send the buffer to the server using our socket
	serverAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error resolving server address:", err)
		os.Exit(1)
	}
	_, err = socket.WriteTo(reqBuffer.Buf[:reqBuffer.Pos], serverAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error sending packet to server:", err)
		os.Exit(1)
	}

	// Prepare for receiving the response
	var resBuffer dns.BytePacketBuffer
	_, _, err = socket.ReadFrom(resBuffer.Buf[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error receiving response from server:", err)
		os.Exit(1)
	}

	// Parse the response packet and print the details
	resPacket, err := dns.DnsPacketFromBuffer(&resBuffer)
	if err != nil {
		fmt.Println("Error parsing response packet:", err)
		os.Exit(1)
	}

	fmt.Printf("%+v\n", resPacket.Header)
	for _, q := range resPacket.Questions {
		fmt.Printf("%+v\n", q)
	}
	for _, rec := range resPacket.Answers {
		fmt.Printf("%+v\n", rec)
	}
	for _, rec := range resPacket.Authorities {
		fmt.Printf("%+v\n", rec)
	}
	for _, rec := range resPacket.Resources {
		fmt.Printf("%+v\n", rec)
	}
}
