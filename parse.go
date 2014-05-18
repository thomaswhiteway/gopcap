package gopcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
	"time"
)

var magic = []byte{0xa1, 0xb2, 0xc3, 0xd4}
var magic_reverse = []byte{0xd4, 0xc3, 0xb2, 0xa1}

// checkMagicNum checks the first four bytes of a pcap file, searching for the magic number
// and checking the byte order. Returns three values: whether the file is a pcap file, whether
// the byte order needs flipping, and any error that was encountered. If error is returned,
// the other values are invalid.
func checkMagicNum(src io.Reader) (bool, binary.ByteOrder, error) {
	// These magic numbers form the header of a pcap file.

	buffer := make([]byte, len(magic))
	readCount, err := src.Read(buffer)

	switch {
	case readCount != len(magic):
		// Failed to read enough bytes for the magic number
		return false, nil, InsufficientLength
	case err != nil && err != io.EOF:
		// Unexpected error
		return false, nil, err
	case bytes.Equal(buffer, magic):
		// Big endian
		return true, binary.BigEndian, nil
	case bytes.Equal(buffer, magic_reverse):
		// Little endian
		return true, binary.LittleEndian, nil
	default:
		// Unrecognised magic number
		return false, nil, NotAPcapFile
	}
}

func (pkt *Packet) ReadFrom(src io.Reader, order binary.ByteOrder, linkType Link) error {

	err := pkt.readPacketHeader(src, order)

	if err != nil {
		return err
	}

	packetReader := io.LimitReader(src, int64(pkt.IncludedLen))

	pkt.Data, err = readLinkData(packetReader, order, linkType)

	// Read any remaining data in the packet that wasn't parsed.
	ioutil.ReadAll(packetReader)

	if err != nil {
		return err
	}

	return nil
}

// readFileHeader reads the next 20 bytes out of the .pcap file and uses it to populate the
// PcapFile structure.
func (file *PcapFile) readFileHeader(src io.Reader, order binary.ByteOrder) error {
	return readFields(src, order, []interface{}{
		&file.MajorVersion,
		&file.MinorVersion,
		&file.TZCorrection,
		&file.SigFigs,
		&file.MaxLen,
		&file.LinkType,
	})
}

// readPacketHeader reads the next 16 bytes out of the file and builds it into a
// packet header.
func (pkt *Packet) readPacketHeader(src io.Reader, order binary.ByteOrder) error {
	var ts_seconds, ts_micros uint32

	err := readFields(src, order, []interface{}{
		&ts_seconds,
		&ts_micros,
		&pkt.IncludedLen,
		&pkt.ActualLen,
	})

	if err == io.ErrUnexpectedEOF {
		return InsufficientLength
	}
	if err != nil {
		return err
	}

	// Construct the timestamp
	pkt.Timestamp = (time.Duration(ts_seconds) * time.Second) + (time.Duration(ts_micros) * time.Microsecond)

	return err
}

// readLinkData takes the data buffer containing the full link-layer packet (or equivalent, e.g.
// Ethernet frame) and builds an appropriate in-memory representation.
func readLinkData(src io.Reader, order binary.ByteOrder, linkType Link) (LinkLayer, error) {
	var pkt LinkLayer

	switch linkType {
	case ETHERNET:
		pkt = new(EthernetFrame)
	default:
		pkt = new(UnknownLink)
	}

	err := pkt.ReadFrom(src)
	return pkt, err
}
