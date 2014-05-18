package gopcap

import (
	"io"
	"io/ioutil"
)

//-----------------------------------------------------------------------------
// TCPSegment
//-----------------------------------------------------------------------------

// TCPSegment represents the data for a single Transmission Control Protocol segment. This method of
// storing a TCPSegment is less efficient than storing the binary representation on the wire.
type TCPSegment struct {
	SourcePort      uint16
	DestinationPort uint16
	SequenceNumber  uint32
	AckNumber       uint32
	HeaderSize      uint8
	NS              bool // This should be viewed as a temporary solution for flags: it's hugely space-inefficient,
	CWR             bool // and so I'll probably update the TCPSegment to handle flags differently.
	ECE             bool
	URG             bool
	ACK             bool
	PSH             bool
	RST             bool
	SYN             bool
	FIN             bool
	WindowSize      uint16
	Checksum        uint16
	UrgentOffset    uint16
	OptionData      []byte // This is temporary. We should handle TCP options properly.
	data            []byte
}

func (t *TCPSegment) TransportData() []byte {
	return t.data
}

func (t *TCPSegment) ReadFrom(src io.Reader) error {

	var offsetAndFlags [2]byte

	err := readFields(src, networkByteOrder, []interface{}{
		&t.SourcePort,
		&t.DestinationPort,
		&t.SequenceNumber,
		&t.AckNumber,
		&offsetAndFlags,
		&t.WindowSize,
		&t.Checksum,
		&t.UrgentOffset,
	})

	if err != nil {
		return err
	}

	// The header size is the top four bits of the next byte.
	t.HeaderSize = uint8(offsetAndFlags[0]) >> 4

	// Now we have all the flag fields. First, the NS flag.
	if (uint8(offsetAndFlags[0]) & 0x01) != 0 {
		t.NS = true
	}

	// The next eight flags are all in the next byte.
	flags := uint8(offsetAndFlags[1])
	if (flags & 0x80) != 0 {
		t.CWR = true
	}
	if (flags & 0x40) != 0 {
		t.ECE = true
	}
	if (flags & 0x20) != 0 {
		t.URG = true
	}
	if (flags & 0x10) != 0 {
		t.ACK = true
	}
	if (flags & 0x08) != 0 {
		t.PSH = true
	}
	if (flags & 0x04) != 0 {
		t.RST = true
	}
	if (flags & 0x02) != 0 {
		t.SYN = true
	}
	if (flags & 0x01) != 0 {
		t.FIN = true
	}

	// If the header size is larger than 5 (it's measured in 32-bit words for reasons that escape me),
	// we have some number of extra bytes that form the TCP options.
	extraBytes := (t.HeaderSize - 5) * 4
	t.OptionData = make([]byte, extraBytes)
	readCount, err := src.Read(t.OptionData)

	if readCount < int(extraBytes) {
		return InsufficientLength
	}

	if err != nil && err != io.EOF {
		return err
	}

	// All that remains is the contained data.
	t.data, err = ioutil.ReadAll(src)

	return err
}
