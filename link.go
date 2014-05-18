package gopcap

import (
	"encoding/binary"
	"io"
)

// The minimum value of the EtherType field. If the value is less than this, it's a length.
// The above statement isn't entirely true, but it's true enough.
const minEtherType uint16 = 1536

//-------------------------------------------------------------------------------------------
// UnknownLink
//-------------------------------------------------------------------------------------------

// UnknownLink represents the data for a link type that gopcap doesn't understand. It simply
// provides uninterpreted data representing the entire link-layer packet.
type UnknownLink struct {
	data InternetLayer
}

func (u *UnknownLink) LinkData() InternetLayer {
	return u.data
}

func (u *UnknownLink) ReadFrom(src io.Reader) error {
	u.data = new(UnknownINet)
	err := u.data.ReadFrom(src)
	return err
}

//-------------------------------------------------------------------------------------------
// EthernetFrame
//-------------------------------------------------------------------------------------------

// EthernetFrame represents a single ethernet frame. Valid only when the LinkType is ETHERNET.
type EthernetFrame struct {
	MACSource      [6]byte
	MACDestination [6]byte
	VLANTag        []byte
	Length         uint16
	EtherType      EtherType
	data           InternetLayer
}

func (e *EthernetFrame) LinkData() InternetLayer {
	return e.data
}

// Given a series of bytes, populate the EthernetFrame structure.
func (e *EthernetFrame) ReadFrom(src io.Reader) error {

	err := readFields(src, networkByteOrder, []interface{}{
		&e.MACDestination,
		&e.MACSource,
	})

	if err != nil {
		return err
	}

	nextValue := uint16(0)
	err = binary.Read(src, networkByteOrder, &nextValue)
	if err != nil {
		return err
	}

	// Check for a VLAN tag.
	if nextValue == 0x8100 {
		vlanTag := make([]byte, 4)
		vlanTag[0] = 0x81
		vlanTag[1] = 0x00

		_, err = src.Read(vlanTag[2:])
		if err != nil {
			return err
		}

		e.VLANTag = vlanTag

		// Re-read the next value
		err = binary.Read(src, networkByteOrder, &nextValue)
		if err != nil {
			return err
		}
	}

	// Read the size or type
	if nextValue < minEtherType {
		e.Length = nextValue
	} else {
		e.EtherType = EtherType(nextValue)
	}

	// Everything else is payload data.
	return e.readInternetLayer(src)
}

// buildInternetLayer creates the internet layer sub-data for a link layer datagram.
func (e *EthernetFrame) readInternetLayer(src io.Reader) error {
	switch e.EtherType {
	case ETHERTYPE_IPV4:
		e.data = new(IPv4Packet)
	case ETHERTYPE_IPV6:
		e.data = new(IPv6Packet)
	default:
		e.data = new(UnknownINet)
	}
	return e.data.ReadFrom(src)

}
