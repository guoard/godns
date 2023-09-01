package dns

type DnsQuestion struct {
	Name  string
	Qtype QueryType
}

func newDnsQuestion(name string, qtype QueryType) DnsQuestion {
	return DnsQuestion{
		Name:  name,
		Qtype: qtype,
	}
}

func (dq *DnsQuestion) read(buffer *BytePacketBuffer) error {
	err := buffer.readQname(&dq.Name)
	if err != nil {
		return err
	}

	qtypeNum, err := buffer.readU16() // qtype
	if err != nil {
		return err
	}
	dq.Qtype = QueryType(qtypeNum)

	_, err = buffer.readU16() // class
	if err != nil {
		return err
	}

	return nil
}

func (dq *DnsQuestion) write(buffer *BytePacketBuffer) error {
	err := buffer.writeQname(dq.Name)
	if err != nil {
		return err
	}

	err = buffer.writeU16(uint16(dq.Qtype))
	if err != nil {
		return err
	}
	
	err = buffer.writeU16(1)
	if err != nil {
		return err
	}

	return nil
}