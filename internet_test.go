package gopcap

import (
	"bytes"
	"reflect"
	"testing"
)

func TestIPv4Good(t *testing.T) {
	// Pull some test data.
	data := []byte{
		0x45, 0x00, 0x00, 0x52, 0x76, 0xED, 0x40, 0x00, 0x40, 0x06, 0x56, 0xCF, 0xC0, 0xA8, 0x01, 0x02, 0xD4, 0xCC, 0xD6, 0x72, 0x0B, 0x20, 0x1A, 0x0B, 0x4D, 0xC8,
		0x4E, 0xED, 0x54, 0xF1, 0x10, 0x72, 0x80, 0x18, 0x1F, 0x4B, 0x6D, 0x2E, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0A, 0x00, 0xD8, 0xEA, 0x48, 0x82, 0xE4, 0xDA, 0xB0,
		0x49, 0x53, 0x4F, 0x4E, 0x20, 0x54, 0x68, 0x75, 0x6E, 0x66, 0x69, 0x73, 0x63, 0x68, 0x20, 0x53, 0x6D, 0x69, 0x6C, 0x65, 0x79, 0x20, 0x53, 0x6D, 0x69, 0x6C,
		0x65, 0x79, 0x47, 0x0A,
	}
	expectedSrc := []byte{192, 168, 1, 2}
	expectedDst := []byte{212, 204, 214, 114}
	pkt := new(IPv4Packet)
	err := pkt.FromBytes(data)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if pkt.IHL != uint8(5) {
		t.Errorf("Unexpected IHL: expected %v, got %v", 5, pkt.IHL)
	}
	if pkt.DSCP != uint8(0) {
		t.Errorf("Unexpected DSCP: expected %v, got %v", 0, pkt.DSCP)
	}
	if pkt.ECN != uint8(0) {
		t.Errorf("Unexpected ECN: expected %v, got %v", 0, pkt.ECN)
	}
	if pkt.TotalLength != uint16(82) {
		t.Errorf("Unexpected total length: expected %v, got %v", 82, pkt.TotalLength)
	}
	if pkt.ID != uint16(30445) {
		t.Errorf("Unexpected ID: expected %v, got %v", 30445, pkt.ID)
	}
	if !pkt.DontFragment {
		t.Error("Don't fragment bit unset.")
	}
	if pkt.MoreFragments {
		t.Errorf("More fragments bit set.")
	}
	if pkt.FragmentOffset != uint16(0) {
		t.Errorf("Unexpected fragment offset: expected %v, got %v", 0, pkt.FragmentOffset)
	}
	if pkt.TTL != uint8(64) {
		t.Errorf("Unexpected TTL: expected %v, got %v", 64, pkt.TTL)
	}
	if pkt.Protocol != IPP_TCP {
		t.Errorf("Unexpected protocol: expected %v, got %v", 6, pkt.Protocol)
	}
	if pkt.Checksum != uint16(22223) {
		t.Errorf("Unexpected checksum: expected %v, got %v", 22223, pkt.Checksum)
	}
	if bytes.Compare(pkt.SourceAddress, expectedSrc) != 0 {
		t.Errorf("Unexpected source address: expected %v, got %v", expectedSrc, pkt.SourceAddress)
	}
	if bytes.Compare(pkt.DestAddress, expectedDst) != 0 {
		t.Errorf("Unexpected destination address: expected %v, got %v", expectedDst, pkt.DestAddress)
	}
	if len(pkt.Options) != 0 {
		t.Errorf("Shouldn't have any options: got %v", pkt.Options)
	}
	pkt.InternetData()
}

func TestIPv6Good(t *testing.T) {
	// Pull some test data.
	data := []byte{
		0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x54, 0xdf, 0x2d, 0x24, 0x6b, 0x28, 0x0e, 0xff, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xdb, 0x3d, 0x07, 0x6c, 0x00, 0x0c, 0x50, 0x26, 0x01, 0x02, 0x03, 0x04,
	}
	expectedSrc := []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x54, 0xdf, 0x2d, 0x24, 0x6b, 0x28, 0x0e}
	expectedDst := []byte{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c}
	pkt := new(IPv6Packet)
	err := pkt.FromBytes(data)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if pkt.TrafficClass != uint8(0) {
		t.Errorf("Unexpected traffic class: expected %v, got %v", 0, pkt.TrafficClass)
	}
	if pkt.FlowLabel != uint32(0) {
		t.Errorf("Unexpected flow label: expected %v, got %v", 0, pkt.FlowLabel)
	}
	if pkt.Length != uint16(12) {
		t.Errorf("Unexpected length: expected %v, got %v", 12, pkt.Length)
	}
	if pkt.NextHeader != IPP_UDP {
		t.Errorf("Unexpected next header: expected %v, got %v", IPP_UDP, pkt.NextHeader)
	}
	if pkt.HopLimit != uint8(1) {
		t.Errorf("Unexpected hop limit: expected %v, got %v", 1, pkt.HopLimit)
	}
	if bytes.Compare(pkt.SourceAddress, expectedSrc) != 0 {
		t.Errorf("Unexpected source address: expected %v, got %v", expectedSrc, pkt.SourceAddress)
	}
	if bytes.Compare(pkt.DestinationAddress, expectedDst) != 0 {
		t.Errorf("Unexpected destination address: expected %v, got %v", expectedDst, pkt.DestinationAddress)
	}
	if _, isUDP := pkt.InternetData().(*UDPDatagram); !isUDP {
		t.Errorf("Unexpected transport type: expected UDPDatagram, got %v", reflect.TypeOf(pkt.InternetData()))
	}
}
