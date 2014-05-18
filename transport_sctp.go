package gopcap

import (
	"io"
)

//-----------------------------------------------------------------------------
// SCTPSegment
//-----------------------------------------------------------------------------

// SCTPSegment represents the data for a single Stream Control Transmission Protocol segment.
// This method of storing an SCTPSegment  is less efficient than storing the binary representation
// on the wire.
type SCTPSegment struct {
	SourcePort      uint16
	DestinationPort uint16
	VerificationTag uint32
	Checksum        uint32
	Chunks          []SCTPChunk
}

func (s *SCTPSegment) TransportData() []byte {
	// Extract the data from data chunks in the packet
	data := make([]byte, 0)
	for _, chunk := range s.Chunks {
		dataChunk, isData := chunk.(*SCTPChunkData)
		if isData {
			data = append(data, dataChunk.Data...)
		}
	}

	return data
}

func (s *SCTPSegment) ReadFrom(src io.Reader) error {
	err := readFields(src, networkByteOrder, []interface{}{
		&s.SourcePort,
		&s.DestinationPort,
		&s.VerificationTag,
		&s.Checksum,
	})

	if err != nil {
		return err
	}

	// Read the chunks from the rest of the request
	chunks, err := readSCTPChunks(src)
	if err != nil {
		return err
	}

	s.Chunks = chunks

	return nil
}
