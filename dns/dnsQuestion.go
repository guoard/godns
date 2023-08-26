package dns

type DnsQuestion struct {
	name  string
	qtype QueryType
}

func newDnsQuestion(name string, qtype QueryType) DnsQuestion {
	return DnsQuestion{
		name:  name,
		qtype: qtype,
	}
}

func (dq *DnsQuestion) read(buffer *BytePacketBuffer) error {
	err := buffer.readQname(&dq.name)
	if err != nil {
		return err
	}

	qtypeNum, err := buffer.readU16() // qtype
	if err != nil {
		return err
	}
	dq.qtype = QueryType(qtypeNum)

	_, err = buffer.readU16() // class
	if err != nil {
		return err
	}

	return nil
}