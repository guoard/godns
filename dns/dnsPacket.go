package dns

import (
	"net"
	"strings"
)

type DnsPacket struct {
	Header      DnsHeader
	Questions   []DnsQuestion
	Answers     []DnsRecord
	Authorities []DnsRecord
	Resources   []DnsRecord
}

func NewDnsPacket() DnsPacket {
	return DnsPacket{
		Header:      NewDnsHeader(),
		Questions:   []DnsQuestion{},
		Answers:     []DnsRecord{},
		Authorities: []DnsRecord{},
		Resources:   []DnsRecord{},
	}
}

func DnsPacketFromBuffer(buffer *BytePacketBuffer) (DnsPacket, error) {
	result := NewDnsPacket()
	err := result.Header.read(buffer)
	if err != nil {
		return result, err
	}

	for i := 0; i < int(result.Header.Questions); i++ {
		question := newDnsQuestion("", UNKNOWN.ToNum())
		err := question.read(buffer)
		if err != nil {
			return result, err
		}
		result.Questions = append(result.Questions, question)
	}

	for i := 0; i < int(result.Header.answers); i++ {
		rec, err := ReadDnsRecord(buffer)
		if err != nil {
			return result, err
		}
		result.Answers = append(result.Answers, rec)
	}

	for i := 0; i < int(result.Header.authoritativeEntries); i++ {
		rec, err := ReadDnsRecord(buffer)
		if err != nil {
			return result, err
		}
		result.Authorities = append(result.Authorities, rec)
	}

	for i := 0; i < int(result.Header.resourceEntries); i++ {
		rec, err := ReadDnsRecord(buffer)
		if err != nil {
			return result, err
		}
		result.Resources = append(result.Resources, rec)
	}

	return result, nil
}

func (p *DnsPacket) Write(buffer *BytePacketBuffer) error {
	p.Header.Questions = uint16(len(p.Questions))
	p.Header.answers = uint16(len(p.Answers))
	p.Header.authoritativeEntries = uint16(len(p.Authorities))
	p.Header.resourceEntries = uint16(len(p.Resources))

	err := p.Header.write(buffer)
	if err != nil {
		return err
	}

	for _, question := range p.Questions {
		err := question.write(buffer)
		if err != nil {
			return err
		}
	}
	for _, rec := range p.Answers {
		_, err := WriteDnsRecord(rec, buffer)
		if err != nil {
			return err
		}
	}
	for _, rec := range p.Authorities {
		_, err := WriteDnsRecord(rec, buffer)
		if err != nil {
			return err
		}
	}
	for _, rec := range p.Resources {
		_, err := WriteDnsRecord(rec, buffer)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *DnsPacket) GetRandomA() net.IP {
	for _, record := range p.Answers {
		aRecord, ok := (record).(ARecord)
		if ok {
			return aRecord.Addr
		}
	}

	return nil
}

func (p *DnsPacket) getNs(qname string) []NSRecord {
	var nsRecords []NSRecord

	for _, record := range p.Authorities {
		nsRecord, ok := record.(NSRecord)
			if ok && strings.HasSuffix(qname, nsRecord.Domain) {
			nsRecords = append(nsRecords, nsRecord)
		}
	}
	return nsRecords
}

func (p *DnsPacket) GetResolvedNs(qname string) net.IP {
	nsRecords := p.getNs(qname)

	for _, nsRecord := range nsRecords {
		for _, record := range p.Resources {
			aRecord, ok := record.(ARecord)
			if ok && aRecord.Domain == nsRecord.Host {
				return aRecord.Addr
			}
		}
	}

	return nil
}

func (p *DnsPacket) GetUnresolvedNS(qname string) string {
	nsRecords := p.getNs(qname)

	for _, nsRecord := range nsRecords {
		return nsRecord.Host
	}

	return ""
}
