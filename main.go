package main

import (
	"fmt"
	"net"
	"os"

	"github.com/guoard/godns/dns"
)

func lookup(qname string, qtype dns.QueryType) (dns.DnsPacket, error) {
	// Forward queries to Google's public DNS
	server := "8.8.8.8:53"

	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 43210})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error binding UDP socket:", err)
		os.Exit(1)
	}
	defer socket.Close()

	packet := dns.DnsPacket{
		Header: dns.DnsHeader{
			Id:               6666,
			Questions:        1,
			RecursionDesired: true,
		},
		Questions: []dns.DnsQuestion{
			{
				Name:  qname,
				Qtype: qtype.ToNum(),
			},
		},
	}

	var reqBuffer dns.BytePacketBuffer
	packet.Write(&reqBuffer)

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

	var resBuffer dns.BytePacketBuffer
	_, _, err = socket.ReadFrom(resBuffer.Buf[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error receiving response from server:", err)
		os.Exit(1)
	}

	return dns.DnsPacketFromBuffer(&resBuffer)
}

// Handle a single incoming packet
func handleQuery(socket *net.UDPConn) error {
	// With a socket ready, we can go ahead and read a packet. This will
	// block until one is received.
	reqBuffer := dns.NewBytePacketBuffer()

	// The `ReadFromUDP` function will read the data into the provided buffer,
	// and return the length of the data read as well as the source address.
	// We're not interested in the length, but we need to keep track of the
	// source in order to send our reply later on.
	_, src, err := socket.ReadFromUDP(reqBuffer.Buf[:])
	if err != nil {
		return err
	}

	// Next, `DnsPacketFromBuffer` is used to parse the raw bytes into
	// a `DnsPacket`.
	request, err := dns.DnsPacketFromBuffer(reqBuffer)
	if err != nil {
		return err
	}

	// Create and initialize the response packet
	packet := dns.NewDnsPacket()
	packet.Header.Id = request.Header.Id
	packet.Header.RecursionDesired = true
	packet.Header.RecursionAvailable = true
	packet.Header.Response = true

	// In the normal case, exactly one question is present
	if len(request.Questions) > 0 {
		question := request.Questions[0]
		fmt.Printf("Received query: %+v\n", question)

		// Since all is set up and as expected, the query can be forwarded to the
		// target server. There's always the possibility that the query will
		// fail, in which case the `SERVFAIL` response code is set to indicate
		// as much to the client. If rather everything goes as planned, the
		// question and response records as copied into our response packet.
		result, err := lookup(question.Name, dns.QueryTypeFromNum(question.Qtype))
		if err == nil {
			packet.Questions = append(packet.Questions, question)
			packet.Header.Rescode = result.Header.Rescode

			for _, rec := range result.Answers {
				fmt.Printf("Answer: %+v\n", rec)
				packet.Answers = append(packet.Answers, rec)
			}
			for _, rec := range result.Authorities {
				fmt.Printf("Authority: %+v\n", rec)
				packet.Authorities = append(packet.Authorities, rec)
			}
			for _, rec := range result.Resources {
				fmt.Printf("Resource: %+v\n", rec)
				packet.Resources = append(packet.Resources, rec)
			}
		} else {
			packet.Header.Rescode = dns.SERVFAIL
		}
	} else {
		// Being mindful of how unreliable input data from arbitrary senders can be, we
		// need make sure that a question is actually present. If not, we return `FORMERR`
		// to indicate that the sender made something wrong.
		packet.Header.Rescode = dns.SERVFAIL
	}

	// The only thing remaining is to encode our response and send it off!
	resBuffer := dns.NewBytePacketBuffer()
	err = packet.Write(resBuffer)
	if err != nil {
		return err
	}

	data, err := resBuffer.GetRange(0, resBuffer.Pos)
	if err != nil {
		return err
	}

	_, err = socket.WriteToUDP(data, src)
	return err
}

func main() {
	// Bind an UDP socket on port 2053
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:2053")
	if err != nil {
		fmt.Printf("Failed to resolve UDP address: %+v\n", err)
		return
	}

	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Printf("Failed to bind UDP socket: %+v\n", err)
		return
	}
	defer socket.Close()

	// For now, queries are handled sequentially, so an infinite loop for servicing
	// requests is initiated.
	for {
		err := handleQuery(socket)
		if err != nil {
			fmt.Printf("An error occurred: %+v\n", err)
		}
	}
}
