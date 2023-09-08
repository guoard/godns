package dns

import (
	"errors"
	"fmt"
	"net"
)

type DnsRecord interface{}

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

type NSRecord struct {
	Domain string
	Host   string
	TTL    uint32
}

type CNAMERecord struct {
	Domain string
	Host   string
	TTL    uint32
}

type MXRecord struct {
	Domain   string
	Priority uint16
	Host     string
	TTL      uint32
}

type AAAARecord struct {
	Domain string
	Addr   net.IP
	TTL    uint32
}

func ReadDnsRecord(buffer *BytePacketBuffer) (DnsRecord, error) {
	var domain string
	err := buffer.ReadQname(&domain)
	if err != nil {
		return nil, err
	}

	qtypeNum, err := buffer.ReadU16()
	if err != nil {
		return nil, err
	}
	qtype := QueryTypeFromNum(qtypeNum)

	_, err = buffer.ReadU16()
	if err != nil {
		return nil, err
	}

	ttl, err := buffer.ReadU32()
	if err != nil {
		return nil, err
	}

	dataLen, err := buffer.ReadU16()
	if err != nil {
		return nil, err
	}

	switch qtype {
	case A:
		rawAddr, err := buffer.ReadU32()
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

	case AAAA:
		rawAddr1, err := buffer.ReadU32()
		if err != nil {
			return nil, err
		}
		rawAddr2, err := buffer.ReadU32()
		if err != nil {
			return nil, err
		}
		rawAddr3, err := buffer.ReadU32()
		if err != nil {
			return nil, err
		}
		rawAddr4, err := buffer.ReadU32()
		if err != nil {
			return nil, err
		}

		addr := net.IP{
			byte((rawAddr1 >> 16) & 0xFFFF), byte(rawAddr1 & 0xFFFF),
			byte((rawAddr2 >> 16) & 0xFFFF), byte(rawAddr2 & 0xFFFF),
			byte((rawAddr3 >> 16) & 0xFFFF), byte(rawAddr3 & 0xFFFF),
			byte((rawAddr4 >> 16) & 0xFFFF), byte(rawAddr4 & 0xFFFF),
		}

		return AAAARecord{
			Domain: domain,
			Addr:   addr,
			TTL:    ttl,
		}, nil

	case NS:
		var ns string
		err := buffer.ReadQname(&ns)
		if err != nil {
			return nil, err
		}

		return NSRecord{
			Domain: domain,
			Host:   ns,
			TTL:    ttl,
		}, nil

	case CNAME:
		var cname string
		err := buffer.ReadQname(&cname)
		if err != nil {
			return nil, err
		}

		return NSRecord{
			Domain: domain,
			Host:   cname,
			TTL:    ttl,
		}, nil

	case MX:
		priority, err := buffer.ReadU16()
		if err != nil {
			return nil, err
		}
		var mx string
		err = buffer.ReadQname(&mx)
		if err != nil {
			return nil, err
		}

		return MXRecord{
			Domain:   domain,
			Priority: priority,
			Host:     mx,
			TTL:      ttl,
		}, nil

	default:
		err := buffer.Step(int(dataLen))
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

// TODO: handle errors for all writes
func WriteDnsRecord(dr DnsRecord, buffer *BytePacketBuffer) (int, error) {
	startPos := buffer.Pos

	switch record := (dr).(type) {
	case ARecord:
		buffer.WriteQname(record.Domain)
		buffer.WriteU16(A.ToNum())
		buffer.WriteU16(1)
		buffer.WriteU32(record.TTL)
		buffer.WriteU16(4)

		octets := record.Addr.To4()
		buffer.WriteU8(octets[0])
		buffer.WriteU8(octets[1])
		buffer.WriteU8(octets[2])
		buffer.WriteU8(octets[3])
	case NSRecord:
		buffer.WriteQname(record.Domain)
		buffer.WriteU16(NS.ToNum())
		buffer.WriteU16(1)
		buffer.WriteU32(record.TTL)

		pos := buffer.Pos
		buffer.WriteU16(0)

		buffer.WriteQname(record.Host)

		size := buffer.Pos - (pos + 2)
		buffer.SetU16(pos, uint16(size))

	case CNAMERecord:
		err := buffer.WriteQname(record.Domain)
		if err != nil {
			return 0, err
		}

		err = buffer.WriteU16(CNAME.ToNum())
		if err != nil {
			return 0, err
		}

		err = buffer.WriteU16(1)
		if err != nil {
			return 0, err
		}

		err = buffer.WriteU32(record.TTL)
		if err != nil {
			return 0, err
		}

		pos := buffer.Pos
		err = buffer.WriteU16(0)
		if err != nil {
			return 0, err
		}

		err = buffer.WriteQname(record.Host)
		if err != nil {
			return 0, err
		}

		size := buffer.Pos - (pos + 2)
		err = buffer.SetU16(pos, uint16(size))
		if err != nil {
			return 0, err
		}

	case MXRecord:
		buffer.WriteQname(record.Domain)
		buffer.WriteU16(MX.ToNum())
		buffer.WriteU16(1)
		buffer.WriteU32(record.TTL)

		pos := buffer.Pos
		buffer.WriteU16(0)

		buffer.WriteU16(record.Priority)
		buffer.WriteQname(record.Host)

		size := buffer.Pos - (pos + 2)
		buffer.SetU16(pos, uint16(size))

	case AAAARecord:
		buffer.WriteQname(record.Domain)
		buffer.WriteU16(AAAA.ToNum())
		buffer.WriteU16(1)
		buffer.WriteU32(record.TTL)
		buffer.WriteU16(16)

		for octet := range record.Addr.To16() {
			buffer.WriteU16(uint16(octet))
		}

	case UnknownRecord:
		fmt.Printf("Skipping record: %+v\n", record)
	default:
		return 0, errors.New("unknown record type")
	}

	return buffer.Pos - startPos, nil
}
