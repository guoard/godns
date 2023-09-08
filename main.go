package main

import (
	"fmt"
	"net"
	"os"

	"github.com/guoard/godns/dns"
)

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

func lookup(qname string, qtype dns.QueryType, server net.UDPAddr) (dns.DnsPacket, error) {
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

	_, err = socket.WriteTo(reqBuffer.Buf[:reqBuffer.Pos], &server)
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
	reqBuffer := dns.NewBytePacketBuffer()

	_, src, err := socket.ReadFromUDP(reqBuffer.Buf[:])
	if err != nil {
		return err
	}

	request, err := dns.DnsPacketFromBuffer(reqBuffer)
	if err != nil {
		return err
	}

	packet := dns.NewDnsPacket()
	packet.Header.Id = request.Header.Id
	packet.Header.RecursionDesired = true
	packet.Header.RecursionAvailable = true
	packet.Header.Response = true

	if len(request.Questions) > 0 {
		question := request.Questions[0]
		fmt.Printf("Received query: %+v\n", question)

		result, err := recursiveLookup(question.Name, dns.QueryTypeFromNum(question.Qtype))
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
		packet.Header.Rescode = dns.SERVFAIL
	}

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

func recursiveLookup(qname string, qtype dns.QueryType) (*dns.DnsPacket, error) {
	// For now we're always starting with *a.root-servers.net*.
	ns := net.ParseIP("198.41.0.4").To4()
	if ns == nil {
		return nil, fmt.Errorf("failed to parse initial nameserver IP")
	}

	for {
		fmt.Printf("attempting lookup of %v %s with ns %s\n", qtype, qname, ns.String())

		server := net.UDPAddr{IP: ns, Port: 53}
		response, err := lookup(qname, qtype, server)
		if err != nil {
			return nil, err
		}

		if len(response.Answers) > 0 && response.Header.Rescode == dns.NOERROR {
			return &response, nil
		}

		if response.Header.Rescode == dns.NXDOMAIN {
			return &response, nil
		}

		newNS := response.GetResolvedNs(qname)
		if newNS != nil {
			ns = newNS
			continue
		}

		newNSName := response.GetUnresolvedNS(qname)
		if newNSName != "" {
			recursiveResponse, err := recursiveLookup(newNSName, dns.A)
			if err != nil {
				return &response, err
			}

			newNS := recursiveResponse.GetRandomA()
			if newNS != nil {
				ns = newNS
			} else {
				return &response, nil
			}
		} else {
			return &response, nil
		}
	}
}
