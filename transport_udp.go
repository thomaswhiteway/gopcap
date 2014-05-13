package gopcap

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

func (u *UDPDatagram) FromBytes(data []byte) error {
	// Begin by confirming that we have enough data to actually represent a UDP datagram.
	if len(data) < 8 {
		return InsufficientLength
	}

	// Happily, UDP is super simple. This makes this code equally simple.
	u.SourcePort = getUint16(data[0:2], false)
	u.DestinationPort = getUint16(data[2:4], false)
	u.Length = getUint16(data[4:6], false)
	u.Checksum = getUint16(data[6:8], false)

	// All that remains is data.
	u.data = data[8:]

	return nil
}
