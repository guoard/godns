package dns

import (
	"errors"
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
			byte((rawAddr>>24) & 0xFF),
			byte((rawAddr>>16) & 0xFF),
			byte((rawAddr>>8) & 0xFF),
			byte((rawAddr>>0) & 0xFF),
		)

		return ARecord{
			Domain: domain,
			Addr:   addr,
			TTL:    ttl,
		}, nil

	case UNKNOWN:
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

	return nil, errors.New("unknown query type")
}
