package dns

import (
	"errors"
	"fmt"
	"net"
)

type DnsRecord interface {
}

type UnknownRecord struct {
	Domain  string
	QType   uint16
	DataLen uint16
	TTL     uint32
}

type ARecord struct {
	Domain string
	Addr   net.IP
	TTL    uint32
}

func ReadDnsRecord(buffer *BytePacketBuffer) (DnsRecord, error) {
	var domain string
	err := buffer.readQname(&domain)
	if err != nil {
		return nil, err
	}

	qtypeNum, err := buffer.readU16()
	if err != nil {
		return nil, err
	}
	qtype := QueryType(qtypeNum)

	_, err = buffer.readU16()
	if err != nil {
		return nil, err
	}

	ttl, err := buffer.readU32()
	if err != nil {
		return nil, err
	}

	dataLen, err := buffer.readU16()
	if err != nil {
		return nil, err
	}

	switch qtype {
	case A:
		rawAddr, err := buffer.readU32()
		if err != nil {
			return nil, err
		}

		addr := net.IPv4(
			byte((rawAddr>>24)&0xFF),
			byte((rawAddr>>16)&0xFF),
			byte((rawAddr>>8)&0xFF),
			byte((rawAddr>>0)&0xFF),
		)

		return ARecord{
			Domain: domain,
			Addr:   addr,
			TTL:    ttl,
		}, nil

	default:
		err := buffer.step(int(dataLen))
		if err != nil {
			return nil, err
		}

		return UnknownRecord{
			Domain:  domain,
			QType:   qtypeNum,
			DataLen: dataLen,
			TTL:     ttl,
		}, nil
	}
}

func WriteDnsRecord(dr DnsRecord, buffer *BytePacketBuffer) (int, error) {
	startPos := buffer.Pos

	switch record := (dr).(type) {
	case ARecord:
		// TODO: handle errors for all writes
		buffer.writeQname(record.Domain)
		buffer.writeU16(uint16(A))
		buffer.writeU16(1)
		buffer.writeU32(record.TTL)
		buffer.writeU16(4)

		octets := record.Addr.To4()
		buffer.writeU8(octets[0])
		buffer.writeU8(octets[1])
		buffer.writeU8(octets[2])
		buffer.writeU8(octets[3])
	case UnknownRecord:
		fmt.Printf("Skipping record: %+v\n", record)
	default:
		return 0, errors.New("unknown record type")
	}

	return buffer.Pos - startPos, nil
}
