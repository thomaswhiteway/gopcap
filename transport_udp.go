package gopcap

import (
	"io"
)

//-----------------------------------------------------------------------------
// UDPDatagram
//-----------------------------------------------------------------------------

// UDPDatagram represents the data for a single User Datagram Protocol datagram. This method of
// storing a UDPDatagram is less efficient than storing the binary representation on the wire.
type UDPDatagram struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
	data            []byte
}

func (u *UDPDatagram) TransportData() []byte {
	return u.data
}

func (u *UDPDatagram) ReadFrom(src io.Reader) error {
	err := readFields(src, networkByteOrder, []interface{}{
		&u.SourcePort,
		&u.DestinationPort,
		&u.Length,
		&u.Checksum,
	})

	// All that remains is data.
	length := u.Length - 8
	u.data = make([]byte, length)
	readCount, err := src.Read(u.data)
	if uint16(readCount) < length {
		return InsufficientLength
	}

	return err
}
