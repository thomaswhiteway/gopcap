package gopcap

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestCheckMagicNum(t *testing.T) {
	in := [][]byte{
		{0xa1, 0xb2, 0xc3, 0xd4},
		{0xd4, 0xc3, 0xb2, 0xa1},
		{0xd4, 0xc3, 0xb2, 0xa0},
		{0xd4, 0xc3, 0xb2},
	}

	first := []bool{true, true, false, false}
	second := []binary.ByteOrder{
		binary.BigEndian,
		binary.LittleEndian,
		nil,
		nil,
	}
	third := []error{nil, nil, NotAPcapFile, InsufficientLength}

	for i, input := range in {
		reader := bytes.NewReader(input)
		out1, out2, out3 := checkMagicNum(reader)

		if out1 != first[i] {
			t.Errorf("Unexpected first return val: expected %v, got %v.", first[i], out1)
		}

		if out2 != second[i] {
			t.Errorf("Unexpected second return val: expected %v, got %v.", second[i], out2)
		}

		if out3 != third[i] {
			t.Errorf("Unexpected third return val: expected %v, got %v.", third[i], out3)
		}
	}
}

func TestPopulatePacketHeaderGood(t *testing.T) {
	in := bytes.NewReader([]byte{0xfa, 0x4f, 0xef, 0x44, 0x64, 0xfd, 0x09, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00})
	pkt := new(Packet)
	err := pkt.readPacketHeader(in, binary.LittleEndian)
	correct_ts := 321259*time.Hour + 31*time.Minute + 6*time.Second + 654*time.Millisecond + 692*time.Microsecond

	if err != nil {
		t.Errorf("Received unexpected error: %v", err)
	}
	if pkt.Timestamp != correct_ts {
		t.Errorf("Incorrect timestamp: expected %v, got %v", correct_ts, pkt.Timestamp)
	}
	if pkt.IncludedLen != uint32(96) {
		t.Errorf("Incorrect included length: expected %v, got %v", 96, pkt.IncludedLen)
	}
	if pkt.ActualLen != uint32(96) {
		t.Errorf("Incorrect actual length: expected %v, got %v", 96, pkt.ActualLen)
	}
}

func TestPopulatePacketHeaderErr(t *testing.T) {
	in := bytes.NewReader([]byte{0xfa})
	pkt := new(Packet)
	err := pkt.readPacketHeader(in, binary.LittleEndian)

	if err != InsufficientLength {
		t.Errorf("Unexpected error: expected %v, got %v", InsufficientLength, err)
	}
}

func TestPopulateFileHeaderGood(t *testing.T) {
	in := bytes.NewReader([]byte{0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00})
	fle := new(PcapFile)
	err := fle.readFileHeader(in, binary.LittleEndian)

	if err != nil {
		t.Errorf("Received unexpected error: %v", err)
	}
	if fle.MajorVersion != uint16(2) {
		t.Errorf("Incorrectly parsed major version: expected %v, got %v.", 2, fle.MajorVersion)
	}
	if fle.MinorVersion != uint16(4) {
		t.Errorf("Incorrectly parsed minor version: expected %v, got %v.", 4, fle.MinorVersion)
	}
	if fle.TZCorrection != int32(0) {
		t.Errorf("Got nonzero TZ correction: %v.", fle.TZCorrection)
	}
	if fle.SigFigs != uint32(0) {
		t.Errorf("Got nonzero sig figs: %v.", fle.SigFigs)
	}
	if fle.MaxLen != uint32(65535) {
		t.Errorf("Incorrectly parsed maximum len: expected %v, got %v.", 65535, fle.MaxLen)
	}
	if fle.LinkType != ETHERNET {
		t.Errorf("Incorrect link type: expected %v, got %v.", ETHERNET, fle.LinkType)
	}
}

func TestPopulateFileHeaderErr(t *testing.T) {
	in := bytes.NewReader([]byte{0xfa})
	fle := new(PcapFile)
	err := fle.readFileHeader(in, binary.BigEndian)

	if err != UnexpectedEOF {
		t.Errorf("Unexpected error: expected %v, got %v", InsufficientLength, err)
	}
}
