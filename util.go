package gopcap

import (
	"encoding/binary"
	"io"
)

// getUint16 takes a two-element byte slice and returns the uint16 contained within it. If flipped
// is set, assumes the byte order is reversed.
func getUint16(buf []byte, flipped bool) uint16 {
	num := uint16(0)
	first, second := 0, 1

	if flipped {
		first, second = 1, 0
	}

	num = (uint16(buf[first]) << 8) + uint16(buf[second])

	return num
}

// getUint32 takes a four-element byte slice and returns the uint32 contained within it. If flipped
// is set, assumes the byte order is reversed.
func getUint32(buf []byte, flipped bool) uint32 {
	num := uint32(0)
	first, second, third, fourth := 0, 1, 2, 3

	if flipped {
		first, second, third, fourth = 3, 2, 1, 0
	}

	num = (uint32(buf[first]) << 24) + (uint32(buf[second]) << 16) + (uint32(buf[third]) << 8) + uint32(buf[fourth])

	return num
}

// getInt32 takes a four-element byte slice and returns the Int32 contained within it. If flipped
// is set, assumes the byte order is reversed.
func getInt32(buf []byte, flipped bool) int32 {
	num := int32(0)
	first, second, third, fourth := 0, 1, 2, 3

	if flipped {
		first, second, third, fourth = 3, 2, 1, 0
	}

	num = (int32(buf[first]) << 24) + (int32(buf[second]) << 16) + (int32(buf[third]) << 8) + int32(buf[fourth])

	return num
}

func readFields(src io.Reader, order binary.ByteOrder, fields []interface{}) error {
	for _, field := range fields {
		err := binary.Read(src, order, field)
		if err != nil {
			return err
		}
	}

	return nil
}

var networkByteOrder binary.ByteOrder = binary.BigEndian
