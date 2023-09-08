package dns

import (
	"errors"
	"fmt"
	"strings"
)

const maxJumps = 5

// BytePacketBuffer represents a buffer for DNS packet contents.
type BytePacketBuffer struct {
	Buf [512]byte
	Pos int
}

// NewBytePacketBuffer creates a new BytePacketBuffer.
func NewBytePacketBuffer() *BytePacketBuffer {
	return &BytePacketBuffer{}
}

// Step advances the buffer position by a specific number of steps.
func (bpb *BytePacketBuffer) Step(steps int) error {
	bpb.Pos += steps
	return nil
}

// Seek sets the buffer position to a specific value.
func (bpb *BytePacketBuffer) Seek(pos int) error {
	bpb.Pos = pos
	return nil
}

// Read reads a single byte and advances the buffer position.
func (bpb *BytePacketBuffer) Read() (byte, error) {
	if bpb.Pos >= 512 {
		return 0, errors.New("end of buffer")
	}
	res := bpb.Buf[bpb.Pos]
	bpb.Pos++
	return res, nil
}

// Get retrieves a single byte without changing the buffer position.
func (bpb *BytePacketBuffer) Get(pos int) (byte, error) {
	if pos >= 512 {
		return 0, errors.New("end of buffer")
	}
	return bpb.Buf[pos], nil
}

// GetRange retrieves a range of bytes.
func (bpb *BytePacketBuffer) GetRange(start int, length int) ([]byte, error) {
	if start+length >= 512 {
		return nil, errors.New("end of buffer")
	}
	return bpb.Buf[start : start+length], nil
}

// ReadU16 reads two bytes and returns a uint16 value.
func (bpb *BytePacketBuffer) ReadU16() (uint16, error) {
	b1, err := bpb.Read()
	if err != nil {
		return 0, err
	}

	b2, err := bpb.Read()
	if err != nil {
		return 0, err
	}

	res := (uint16(b1) << 8) | uint16(b2)
	return res, nil
}

// ReadU32 reads four bytes and returns a uint32 value.
func (bpb *BytePacketBuffer) ReadU32() (uint32, error) {
	var res uint32
	for i := 0; i < 4; i++ {
		b, err := bpb.Read()
		if err != nil {
			return 0, err
		}
		res = (res << 8) | uint32(b)
	}
	return res, nil
}

// ReadQname reads a DNS domain name from the buffer.
func (bpb *BytePacketBuffer) ReadQname(outstr *string) error {
	pos := bpb.Pos
	jumped := false
	jumpsPerformed := 0
	delim := ""

	for {
		if jumpsPerformed > maxJumps {
			return fmt.Errorf("limit of %d jumps exceeded", maxJumps)
		}

		len, err := bpb.Get(pos)
		if err != nil {
			return err
		}

		if (len & 0xC0) == 0xC0 {
			if !jumped {
				err := bpb.Seek(pos + 2)
				if err != nil {
					return err
				}
			}

			b2, err := bpb.Get(pos + 1)
			if err != nil {
				return err
			}
			offset := (((uint16(len) ^ 0xC0) << 8) | uint16(b2))
			pos = int(offset)

			jumped = true
			jumpsPerformed++

			continue
		} else {
			pos++
			if len == 0 {
				break
			}

			*outstr += delim

			strBuffer, err := bpb.GetRange(pos, int(len))
			if err != nil {
				return err
			}
			*outstr += strings.ToLower(string(strBuffer))

			delim = "."
			pos += int(len)
		}
	}

	if !jumped {
		err := bpb.Seek(pos)
		if err != nil {
			return err
		}
	}

	return nil
}

// Write writes a single byte to the buffer and advances the position.
func (bpb *BytePacketBuffer) Write(val uint8) error {
	if bpb.Pos >= 512 {
		return errors.New("end of buffer")
	}
	bpb.Buf[bpb.Pos] = val
	bpb.Pos++
	return nil
}

// WriteU8 writes a uint8 value to the buffer.
func (bpb *BytePacketBuffer) WriteU8(val uint8) error {
	return bpb.Write(val)
}

// WriteU16 writes a uint16 value to the buffer.
func (bpb *BytePacketBuffer) WriteU16(val uint16) error {
	err := bpb.Write(uint8(val >> 8))
	if err != nil {
		return err
	}

	err = bpb.Write(uint8(val & 0xFF))
	if err != nil {
		return err
	}

	return nil
}

// WriteU32 writes a uint32 value to the buffer.
func (bpb *BytePacketBuffer) WriteU32(val uint32) error {
	for i := 3; i >= 0; i-- {
		err := bpb.Write(uint8((val >> (8 * i)) & 0xFF))
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteQname writes a DNS domain name to the buffer.
func (bpb *BytePacketBuffer) WriteQname(qname string) error {
	for _, label := range strings.Split(qname, ".") {
		len := len(label)
		if len > 0x3f {
			return errors.New("single label exceeds 63 characters of length")
		}

		err := bpb.WriteU8(uint8(len))
		if err != nil {
			return err
		}

		for _, b := range []byte(label) {
			err := bpb.WriteU8(b)
			if err != nil {
				return err
			}
		}
	}

	return bpb.WriteU8(0)
}

// ResultCode represents a DNS result code.
type ResultCode int

const (
	NOERROR ResultCode = iota
	FORMERR
	SERVFAIL
	NXDOMAIN
	NOTIMP
	REFUSED
)

// DnsHeader represents a DNS packet header.
type DnsHeader struct {
	Id                   uint16
	RecursionDesired     bool
	TruncatedMessage     bool
	AuthoritativeAnswer  bool
	Opcode               uint8
	Response             bool
	Rescode              ResultCode
	CheckingDisabled     bool
	AuthedData           bool
	Z                    bool
	RecursionAvailable   bool
	Questions            uint16
	Answers              uint16
	AuthoritativeEntries uint16
	ResourceEntries      uint16
}

// NewDnsHeader creates a new DnsHeader.
func NewDnsHeader() DnsHeader {
	return DnsHeader{}
}

// Read reads a DNS header from the buffer.
func (header *DnsHeader) Read(buffer *BytePacketBuffer) error {
	id, err := buffer.ReadU16()
	if err != nil {
		return err
	}

	header.Id = id

	flags1, err := buffer.Read()
	if err != nil {
		return err
	}

	flags2, err := buffer.Read()
	if err != nil {
		return err
	}

	header.RecursionDesired = flags1&(1<<0) > 0
	header.TruncatedMessage = flags1&(1<<1) > 0
	header.AuthoritativeAnswer = flags1&(1<<2) > 0
	header.Opcode = (flags1 >> 3) & 0x0F
	header.Response = flags1&(1<<7) > 0

	header.Rescode = ResultCode(flags2 & 0x0F)
	header.CheckingDisabled = flags2&(1<<4) > 0
	header.AuthedData = flags2&(1<<5) > 0
	header.Z = flags2&(1<<6) > 0
	header.RecursionAvailable = flags2&(1<<7) > 0

	header.Questions, err = buffer.ReadU16()
	if err != nil {
		return err
	}

	header.Answers, err = buffer.ReadU16()
	if err != nil {
		return err
	}

	header.AuthoritativeEntries, err = buffer.ReadU16()
	if err != nil {
		return err
	}

	header.ResourceEntries, err = buffer.ReadU16()
	if err != nil {
		return err
	}

	return nil
}

// Write writes a DNS header to the buffer.
func (h *DnsHeader) Write(buffer *BytePacketBuffer) error {
	err := buffer.WriteU16(h.Id)
	if err != nil {
		return err
	}

	flags1 := uint8(boolToUint(h.RecursionDesired)) |
		uint8(boolToUint(h.TruncatedMessage))<<1 |
		uint8(boolToUint(h.AuthoritativeAnswer))<<2 |
		(h.Opcode << 3) |
		uint8(boolToUint(h.Response))<<7

	err = buffer.Write(flags1)
	if err != nil {
		return err
	}

	flags2 := uint8(h.Rescode) |
		uint8(boolToUint(h.CheckingDisabled))<<4 |
		uint8(boolToUint(h.AuthedData))<<5 |
		uint8(boolToUint(h.Z))<<6 |
		uint8(boolToUint(h.RecursionAvailable))<<7

	err = buffer.Write(flags2)
	if err != nil {
		return err
	}

	err = buffer.WriteU16(h.Questions)
	if err != nil {
		return err
	}

	err = buffer.WriteU16(h.Answers)
	if err != nil {
		return err
	}

	err = buffer.WriteU16(h.AuthoritativeEntries)
	if err != nil {
		return err
	}

	err = buffer.WriteU16(h.ResourceEntries)
	if err != nil {
		return err
	}

	return nil
}

// Set updates a byte in the buffer at the specified position.
func (bpb *BytePacketBuffer) Set(pos int, val byte) error {
	bpb.Buf[pos] = val
	return nil
}

// SetU16 updates two bytes in the buffer at the specified position.
func (bpb *BytePacketBuffer) SetU16(pos int, val uint16) error {
	err := bpb.Set(pos, byte(val>>8))
	if err != nil {
		return err
	}

	err = bpb.Set(pos+1, byte(val&0xFF))
	if err != nil {
		return err
	}

	return nil
}

func boolToUint(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
