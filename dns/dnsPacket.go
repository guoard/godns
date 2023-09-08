package dns

import (
	"net"
	"strings"
)

// DnsPacket represents a DNS packet.
type DnsPacket struct {
	Header      DnsHeader
	Questions   []DnsQuestion
	Answers     []DnsRecord
	Authorities []DnsRecord
	Resources   []DnsRecord
}

// NewDnsPacket creates a new DnsPacket with initialized fields.
func NewDnsPacket() DnsPacket {
	return DnsPacket{
		Header:      NewDnsHeader(),
		Questions:   []DnsQuestion{},
		Answers:     []DnsRecord{},
		Authorities: []DnsRecord{},
		Resources:   []DnsRecord{},
	}
}

// DnsPacketFromBuffer creates a DnsPacket from a BytePacketBuffer.
func DnsPacketFromBuffer(buffer *BytePacketBuffer) (DnsPacket, error) {
	result := NewDnsPacket()
	err := result.Header.Read(buffer)
	if err != nil {
		return result, err
	}

	for i := 0; i < int(result.Header.Questions); i++ {
		question := NewDnsQuestion("", UNKNOWN.ToNum())
		err := question.Read(buffer)
		if err != nil {
			return result, err
		}
		result.Questions = append(result.Questions, question)
	}

	for i := 0; i < int(result.Header.Answers); i++ {
		rec, err := ReadDnsRecord(buffer)
		if err != nil {
			return result, err
		}
		result.Answers = append(result.Answers, rec)
	}

	for i := 0; i < int(result.Header.AuthoritativeEntries); i++ {
		rec, err := ReadDnsRecord(buffer)
		if err != nil {
			return result, err
		}
		result.Authorities = append(result.Authorities, rec)
	}

	for i := 0; i < int(result.Header.ResourceEntries); i++ {
		rec, err := ReadDnsRecord(buffer)
		if err != nil {
			return result, err
		}
		result.Resources = append(result.Resources, rec)
	}

	return result, nil
}

// Write writes the DnsPacket to a BytePacketBuffer.
func (p *DnsPacket) Write(buffer *BytePacketBuffer) error {
	p.Header.Questions = uint16(len(p.Questions))
	p.Header.Answers = uint16(len(p.Answers))
	p.Header.AuthoritativeEntries = uint16(len(p.Authorities))
	p.Header.ResourceEntries = uint16(len(p.Resources))

	err := p.Header.Write(buffer)
	if err != nil {
		return err
	}

	for _, question := range p.Questions {
		err := question.Write(buffer)
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

// GetRandomA retrieves a random A record from the Answers section.
func (p *DnsPacket) GetRandomA() net.IP {
	for _, record := range p.Answers {
		aRecord, ok := record.(ARecord)
		if ok {
			return aRecord.Addr
		}
	}
	return nil
}

// getNs retrieves NS records matching the domain suffix.
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

// GetResolvedNs retrieves the resolved IP for an NS record matching the domain suffix.
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

// GetUnresolvedNS retrieves the host of the first NS record matching the domain suffix.
func (p *DnsPacket) GetUnresolvedNS(qname string) string {
	nsRecords := p.getNs(qname)

	for _, nsRecord := range nsRecords {
		return nsRecord.Host
	}

	return ""
}
