package dns

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

	for i := 0; i < int(result.Header.questions); i++ {
			question := newDnsQuestion("", UNKNOWN)
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