package dns

import (
	"errors"
	"fmt"
	"strings"
)

type BytePacketBuffer struct {
	Buf [512]byte
	pos int
}

// This gives us a fresh buffer for holding the packet contents, and a
// field for keeping track of where we are.
func NewBytePacketBuffer() *BytePacketBuffer {
	return &BytePacketBuffer{}
}

// Step the buffer position forward a specific number of steps
func (bpb *BytePacketBuffer) step(steps int) error {
	bpb.pos += steps
	return nil
}

// Change the buffer position
func (bpb *BytePacketBuffer) seek(pos int) error {
	bpb.pos = pos
	return nil
}

// Read a single byte and move the position one step forward
func (bpb *BytePacketBuffer) read() (byte, error) {
	if bpb.pos >= 512 {
		return 0, errors.New("end of buffer")
	}
	res := bpb.Buf[bpb.pos]
	bpb.pos += 1

	return res, nil
}

// Get a single byte, without changing the buffer position
func (bpb *BytePacketBuffer) get(pos int) (byte, error) {
	if pos >= 512 {
		return 0, errors.New("end of buffer")
	}
	return bpb.Buf[pos], nil
}

// Get a range of bytes
func (bpb *BytePacketBuffer) getRange(start int, length int) ([]byte, error) {
	if start + length >= 512 {
		return nil, errors.New("end of buffer")
	}
	return bpb.Buf[start : start + length], nil
}

// Read two bytes, stepping two steps forward
func (bpb *BytePacketBuffer) readU16() (uint16, error) {
	b1, err := bpb.read()
	if err != nil {
		return 0, err
	}

	b2, err := bpb.read()
	if err != nil {
		return 0, err
	}

	res := (uint16(b1) << 8) | uint16(b2)
	return res, nil
}

// Read four bytes, stepping four steps forward
func (bpb *BytePacketBuffer) readU32() (uint32, error) {
	b1, err := bpb.read()
	if err != nil {
		return 0, err
	}

	b2, err := bpb.read()
	if err != nil {
		return 0, err
	}

	b3, err := bpb.read()
	if err != nil {
		return 0, err
	}

	b4, err := bpb.read()
	if err != nil {
		return 0, err
	}

	res := (uint32(b1) << 24) | (uint32(b2) << 16) | (uint32(b3) << 8) | uint32(b4)
	return res, nil
}

// Read a qname
//
// The tricky part: Reading domain names, taking labels into consideration.
// Will take something like [3]www[6]google[3]com[0] and append
// www.google.com to outstr.
func (bpb *BytePacketBuffer) readQname(outstr *string) error {
	// Since we might encounter jumps, we'll keep track of our position
	// locally as opposed to using the position within the struct. This
	// allows us to move the shared position to a point past our current
	// qname, while keeping track of our progress on the current qname
	// using this variable.
	pos := bpb.pos

	// track whether or not we've jumped
	jumped := false
	maxJumps := 5
	jumpsPerformed := 0

	// Our delimiter which we append for each label. Since we don't want a
	// dot at the beginning of the domain name we'll leave it empty for now
	// and set it to "." at the end of the first iteration.
	delim := ""
	for {
		// Dns Packets are untrusted data, so we need to be paranoid. Someone
		// can craft a packet with a cycle in the jump instructions. This guards
		// against such packets.
		if jumpsPerformed > maxJumps {
			return fmt.Errorf("limit of %d jumps exceeded", maxJumps)
		}

		// At this point, we're always at the beginning of a label.
		// labels start with a length byte.
		len, err := bpb.get(pos)
		if err != nil {
			return err
		}

		// If len has the two most significant bit are set, it represents a
		// jump to some other offset in the packet:
		if (len & 0xC0) == 0xC0 {
			// Update the buffer position to a point past the current
			// label. We don't need to touch it any further.
			if !jumped {
				err := bpb.seek(pos + 2)
				if err != nil {
					return err
				}
			}

			// Read another byte, calculate offset and perform the jump by
			// updating our local position variable
			b2, err := bpb.get(pos + 1)
			if err != nil {
				return err
			}
			offset := (((uint16(len) ^ 0xC0) << 8) | uint16(b2))
			pos = int(offset)

			// Indicate that a jump was performed.
			jumped = true
			jumpsPerformed += 1

			continue
			} else {
			// The base scenario, where we're reading a single label and
			// appending it to the output:

			// Move a single byte forward to move past the length byte.
			pos += 1
			
			// Domain names are terminated by an empty label of length 0,
			// so if the length is zero we're done.
			if len == 0 {
				break
			}

			// Append the delimiter to our output buffer first.
			*outstr += delim

			// Extract the actual ASCII bytes for this label and append them
			// to the output buffer.
			strBuffer, err := bpb.getRange(pos, int(len))
			if err != nil {
				return err
			}
			*outstr += strings.ToLower(string(strBuffer))

			delim = "."

			// Move forward the full length of the label.
			pos += int(len)
		}
	}

	if !jumped {
		err := bpb.seek(pos)
		if err != nil {
			return err
		}
	}

	return nil
}

type ResultCode int

const (
	NOERROR  ResultCode = iota
	FORMERR
	SERVFAIL
	NXDOMAIN
	NOTIMP
	REFUSED
)

type DnsHeader struct {
	id                      uint16

	recursion_desired       bool
	truncated_message       bool
	authoritativeAnswer    bool
	opcode                  uint8
	response                bool

	rescode                 ResultCode
	checkingDisabled       bool
	authed_data             bool
	z                       bool
	recursionAvailable     bool

	questions               uint16
	answers                 uint16
	authoritativeEntries   uint16
	resourceEntries        uint16
}

func NewDnsHeader() DnsHeader {
	return DnsHeader{}
}

func (header *DnsHeader) read(buffer *BytePacketBuffer) error {
	id, err := buffer.readU16()
	if err != nil {
		return err
	}

	header.id = id;

	flags, err := buffer.readU16()
	if err != nil {
		return err
	}
	a := uint8(flags >> 8)
	b := uint8(flags & 0xFF)
	header.recursion_desired = (a & (1 << 0)) > 0
	header.truncated_message = (a & (1 << 1)) > 0
	header.authoritativeAnswer = (a & (1 << 2)) > 0
	header.opcode = (a >> 3) & 0x0F
	header.response = (a & (1 << 7)) > 0

	header.rescode = ResultCode(b & 0x0F)
	header.checkingDisabled = (b & (1 << 4)) > 0
	header.authed_data = (b & (1 << 5)) > 0
	header.z = (b & (1 << 6)) > 0
	header.recursionAvailable = (b & (1 << 7)) > 0

	header.questions, err = buffer.readU16()
	if err != nil {
		return err
	}

	header.answers, err = buffer.readU16()
	if err != nil {
		return err
	}

	header.authoritativeEntries, err = buffer.readU16()
	if err != nil {
		return err
	}

	header.resourceEntries, err = buffer.readU16()
	if err != nil {
		return err
	}

	return nil
}