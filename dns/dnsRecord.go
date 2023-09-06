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
	err := buffer.readQname(&domain)
	if err != nil {
		return nil, err
	}

	qtypeNum, err := buffer.readU16()
	if err != nil {
		return nil, err
	}
	qtype := QueryTypeFromNum(qtypeNum)

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

	case AAAA:
		rawAddr1, err := buffer.readU32()
		if err != nil {
			return nil, err
		}
		rawAddr2, err := buffer.readU32()
		if err != nil {
			return nil, err
		}
		rawAddr3, err := buffer.readU32()
		if err != nil {
			return nil, err
		}
		rawAddr4, err := buffer.readU32()
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
		err := buffer.readQname(&ns)
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
		err := buffer.readQname(&cname)
		if err != nil {
			return nil, err
		}

		return NSRecord{
			Domain: domain,
			Host:   cname,
			TTL:    ttl,
		}, nil

	case MX:
		priority, err := buffer.readU16()
		if err != nil {
			return nil, err
		}
		var mx string
		err = buffer.readQname(&mx)
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

// TODO: handle errors for all writes
func WriteDnsRecord(dr DnsRecord, buffer *BytePacketBuffer) (int, error) {
	startPos := buffer.Pos

	switch record := (dr).(type) {
	case ARecord:
		buffer.writeQname(record.Domain)
		buffer.writeU16(A.ToNum())
		buffer.writeU16(1)
		buffer.writeU32(record.TTL)
		buffer.writeU16(4)

		octets := record.Addr.To4()
		buffer.writeU8(octets[0])
		buffer.writeU8(octets[1])
		buffer.writeU8(octets[2])
		buffer.writeU8(octets[3])
	case NSRecord:
		buffer.writeQname(record.Domain)
		buffer.writeU16(NS.ToNum())
		buffer.writeU16(1)
		buffer.writeU32(record.TTL)

		pos := buffer.Pos
		buffer.writeU16(0)

		buffer.writeQname(record.Host)

		size := buffer.Pos - (pos + 2)
		buffer.setU16(pos, uint16(size))

	case CNAMERecord:
		err := buffer.writeQname(record.Domain)
		if err != nil {
			return 0, err
		}

		err = buffer.writeU16(CNAME.ToNum())
		if err != nil {
			return 0, err
		}

		err = buffer.writeU16(1)
		if err != nil {
			return 0, err
		}

		err = buffer.writeU32(record.TTL)
		if err != nil {
			return 0, err
		}

		pos := buffer.Pos
		err = buffer.writeU16(0)
		if err != nil {
			return 0, err
		}

		err = buffer.writeQname(record.Host)
		if err != nil {
			return 0, err
		}

		size := buffer.Pos - (pos + 2)
		err = buffer.setU16(pos, uint16(size))
		if err != nil {
			return 0, err
		}

	case MXRecord:
		buffer.writeQname(record.Domain)
		buffer.writeU16(MX.ToNum())
		buffer.writeU16(1)
		buffer.writeU32(record.TTL)

		pos := buffer.Pos
		buffer.writeU16(0)

		buffer.writeU16(record.Priority)
		buffer.writeQname(record.Host)

		size := buffer.Pos - (pos + 2)
		buffer.setU16(pos, uint16(size))

	case AAAARecord:
		buffer.writeQname(record.Domain)
		buffer.writeU16(AAAA.ToNum())
		buffer.writeU16(1)
		buffer.writeU32(record.TTL)
		buffer.writeU16(16)

		for octet := range record.Addr.To16() {
			buffer.writeU16(uint16(octet))
		}

	case UnknownRecord:
		fmt.Printf("Skipping record: %+v\n", record)
	default:
		return 0, errors.New("unknown record type")
	}

	return buffer.Pos - startPos, nil
}
