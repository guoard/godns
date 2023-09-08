package dns

type DnsQuestion struct {
	Name  string
	Qtype uint16
}

// NewDnsQuestion creates a new DnsQuestion with the provided name and qtype.
func NewDnsQuestion(name string, qtype uint16) DnsQuestion {
	return DnsQuestion{
		Name:  name,
		Qtype: qtype,
	}
}

// Read reads a DNS question from the BytePacketBuffer.
func (dq *DnsQuestion) Read(buffer *BytePacketBuffer) error {
	err := buffer.ReadQname(&dq.Name)
	if err != nil {
		return err
	}

	qtypeNum, err := buffer.ReadU16()
	if err != nil {
		return err
	}
	dq.Qtype = qtypeNum

	_, err = buffer.ReadU16()
	if err != nil {
		return err
	}

	return nil
}

// Write writes a DNS question to the BytePacketBuffer.
func (dq *DnsQuestion) Write(buffer *BytePacketBuffer) error {
	err := buffer.WriteQname(dq.Name)
	if err != nil {
		return err
	}

	err = buffer.WriteU16(uint16(dq.Qtype))
	if err != nil {
		return err
	}

	err = buffer.WriteU16(1)
	if err != nil {
		return err
	}

	return nil
}
