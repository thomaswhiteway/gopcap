package gopcap

import (
	"bytes"
	"io"
)

//-------------------------------------------------------------------------------------------
// UnknownINet
//-------------------------------------------------------------------------------------------

// UnknownINet represents the data for an internet-layer packet that gopcap doesn't understand.
// It simply provides uninterpreted data representing the entire internet-layer packet.
type UnknownINet struct {
	data TransportLayer
}

func (u *UnknownINet) InternetData() TransportLayer {
	return u.data
}

func (u *UnknownINet) ReadFrom(src io.Reader) error {
	u.data = new(UnknownTransport)
	return u.data.ReadFrom(src)
}

//-------------------------------------------------------------------------------------------
// IPv4
//-------------------------------------------------------------------------------------------

// IPv4Packet represents an unpacked IPv4 packet. This method of storing the IPv4 packet data
// is less efficient than the byte-packed form used on the wire.
type IPv4Packet struct {
	IHL            uint8
	DSCP           uint8
	ECN            uint8
	TotalLength    uint16
	ID             uint16
	DontFragment   bool
	MoreFragments  bool
	FragmentOffset uint16
	TTL            uint8
	Protocol       IPProtocol
	Checksum       uint16
	SourceAddress  [4]byte
	DestAddress    [4]byte
	Options        []byte
	data           TransportLayer
}

func (p *IPv4Packet) InternetData() TransportLayer {
	return p.data
}

func (p *IPv4Packet) ReadFrom(src io.Reader) error {
	// The IPv4 header is full of crazy non-aligned fields that I've expanded in the structure.
	// This makes this function a total nightmare. My apologies in advance.

	var versionIHL uint8
	var DSCPECN uint8
	var flagsFragment [2]byte

	err := readFields(src, networkByteOrder, []interface{}{
		&versionIHL,
		&DSCPECN,
		&p.TotalLength,
		&p.ID,
		&flagsFragment,
		&p.TTL,
		&p.Protocol,
		&p.Checksum,
		&p.SourceAddress,
		&p.DestAddress,
	})

	if err != nil {
		return err
	}

	// Check that this actually is an IPv4 packet.
	if uint8((versionIHL&0xF0)>>4) != uint8(4) {
		return IncorrectPacket
	}

	// The header length is the low four bits of the first byte.
	p.IHL = uint8(versionIHL & 0x0F)

	// The DSCP is the high six(!) bits of the second byte.
	p.DSCP = uint8((DSCPECN & 0xFC) >> 2)

	// Congestion notification is the low two bits of the second byte.
	p.ECN = uint8(DSCPECN & 0x03)

	// Back to the crazy with the flags: the top three bits of the 7th byte. We only care
	// about bits two and three. It hurt me to write that sentence.
	if uint16(flagsFragment[0])&0x40 != 0 {
		p.DontFragment = true
	}
	if uint16(flagsFragment[0])&0x20 != 0 {
		p.MoreFragments = true
	}

	// Following from the flag crazy, the fragment offset is the low 13 bits of the 7th
	// and 8th bytes.
	p.FragmentOffset = uint16((flagsFragment[0] & 0x1F) << 8)
	p.FragmentOffset += uint16(flagsFragment[1])

	// If IHL is more than 5, we have (IHL - 5) * 4 bytes of options.
	if p.IHL > 5 {
		optionLength := uint16(p.IHL-5) * 4
		p.Options = make([]byte, optionLength)
		readCount, err := src.Read(p.Options)
		if uint16(readCount) < optionLength {
			return InsufficientLength
		}
		if err != nil {
			return err
		}
	}

	// The data length is the total length, minus the headers. The headers are, for no good
	// reason, measured in 32-bit words, so the data length is actually:
	dataLen := p.TotalLength - (uint16(p.IHL) * 4)

	internetData := make([]byte, dataLen)
	readCount, err := src.Read(internetData)
	if uint16(readCount) < dataLen {
		return InsufficientLength
	}
	if err != nil && err != io.EOF {
		return err
	}

	// Build the transport layer data.
	return p.readTransportLayer(bytes.NewReader(internetData))
}

func (p *IPv4Packet) readTransportLayer(src io.Reader) error {
	switch p.Protocol {
	case IPP_TCP:
		p.data = new(TCPSegment)
	case IPP_UDP:
		p.data = new(UDPDatagram)
	case IPP_SCTP:
		p.data = new(SCTPSegment)
	default:
		p.data = new(UnknownTransport)
	}
	return p.data.ReadFrom(src)
}

//-------------------------------------------------------------------------------------------
// IPv6
//-------------------------------------------------------------------------------------------

type IPv6Packet struct {
	TrafficClass       uint8
	FlowLabel          uint32 // This is a huge waste of space for a 20-bit field. Rethink?
	Length             uint16
	NextHeader         IPProtocol
	HopLimit           uint8
	SourceAddress      [16]byte
	DestinationAddress [16]byte
	data               TransportLayer
}

func (p *IPv6Packet) InternetData() TransportLayer {
	return p.data
}

func (p *IPv6Packet) ReadFrom(src io.Reader) error {

	var startBytes [4]byte

	err := readFields(src, networkByteOrder, []interface{}{
		&startBytes,
		&p.Length,
		&p.NextHeader,
		&p.HopLimit,
		&p.SourceAddress,
		&p.DestinationAddress,
	})

	if err != nil {
		return err
	}

	// Check that this actually is an IPv6 packet.
	if ((uint8(startBytes[0]) & 0xF0) >> 4) != uint8(6) {
		return IncorrectPacket
	}

	// The traffic class is the octet following the version.
	p.TrafficClass = (uint8(startBytes[0]) & 0x0F) << 4
	p.TrafficClass += (uint8(startBytes[1]) & 0xF0) >> 4

	// The flow label is the next 20 bits.
	p.FlowLabel = (uint32(startBytes[1]) & 0x0F) << 16
	p.FlowLabel += uint32(startBytes[2]) << 8
	p.FlowLabel += uint32(startBytes[3])

	// Following the fixed headers are a sequence of extension headers
	// terminating in the transport data.
	return p.readRemainingHeaders(src)
}

func (p *IPv6Packet) readRemainingHeaders(src io.Reader) error {
	// Currently we don't support any extension headers so if the next header
	// isn't the transport data then give up and interpret it as an unknown
	// transport type.
	switch p.NextHeader {
	case IPP_TCP:
		p.data = new(TCPSegment)
	case IPP_UDP:
		p.data = new(UDPDatagram)
	case IPP_SCTP:
		p.data = new(SCTPSegment)
	default:
		p.data = new(UnknownTransport)
	}
	return p.data.ReadFrom(src)
}
