package gopcap

import (
	"bytes"
	"testing"
)

func TestUDPGood(t *testing.T) {
	// Define the data for a UDP datagram.
	data := []byte{
		0x08, 0x50, 0x00, 0x35, 0x00, 0x32, 0x83, 0x97, 0x31, 0x1f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x32, 0x01, 0x31,
		0x03, 0x31, 0x36, 0x38, 0x03, 0x31, 0x39, 0x32, 0x07, 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c,
		0x00, 0x01,
	}

	dgram := new(UDPDatagram)
	err := dgram.ReadFrom(bytes.NewReader(data))

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if dgram.SourcePort != uint16(2128) {
		t.Errorf("Unexpected source port: expected %v, got %v.", 2128, dgram.SourcePort)
	}
	if dgram.DestinationPort != uint16(53) {
		t.Errorf("Unexpected destination port: expected %v, got %v.", 53, dgram.DestinationPort)
	}
	if dgram.Length != uint16(50) {
		t.Errorf("Unexpected length: expected %v, got %v.", 50, dgram.Length)
	}
	if dgram.Checksum != uint16(33687) {
		t.Errorf("Unexpected checksum: expected %v, got %v.", 33687, dgram.Checksum)
	}
	if len(dgram.TransportData()) != 42 {
		t.Errorf("Unexpected length of contained data: expected %v, got %v", 42, len(dgram.TransportData()))
	}
}
