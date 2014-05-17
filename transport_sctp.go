package gopcap

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

func (s *SCTPSegment) FromBytes(data []byte) error {
	// Begin by confirming that we have enough data to actually represent an SCTP segment
	if len(data) < 12 {
		return InsufficientLength
	}

	// The common header for SCTP is very simple.
	s.SourcePort = getUint16(data[0:2], false)
	s.DestinationPort = getUint16(data[2:4], false)
	s.VerificationTag = getUint32(data[4:8], false)
	s.Checksum = getUint32(data[8:12], false)

	// Read the chunks from the rest of the request
	chunks, err := parseSCTPChunks(data[12:])
	if err != nil {
		return err
	}

	s.Chunks = chunks

	return nil
}
