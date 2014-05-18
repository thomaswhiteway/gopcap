package gopcap

import (
	"encoding/binary"
	"io"
	"io/ioutil"
)

// SCTPChunk represents a single SCTP Chunk in an SCTP Segment.
type SCTPChunk interface {
	ChunkType() SCTPChunkType
	ChunkFlags() uint8
	ChunkLength() uint16
	readBodyFrom(src io.Reader) error
	setHeader(header *SCTPChunkHeader)
}

// The common header for all SCTP Chunk types
type SCTPChunkHeader struct {
	Type   SCTPChunkType
	Flags  uint8
	Length uint16
}

func (h *SCTPChunkHeader) ChunkType() SCTPChunkType {
	return h.Type
}

func (h *SCTPChunkHeader) ChunkFlags() uint8 {
	return h.Flags
}

func (h *SCTPChunkHeader) ChunkLength() uint16 {
	return h.Length
}

func (h *SCTPChunkHeader) ReadFrom(src io.Reader) error {
	err := readFields(src, networkByteOrder, []interface{}{
		&h.Type,
		&h.Flags,
		&h.Length,
	})
	if err != nil {
		return err
	}
	return h.readBodyFrom(src)
}

func (h *SCTPChunkHeader) readBodyFrom(src io.Reader) error {
	return nil
}

func (h *SCTPChunkHeader) setHeader(header *SCTPChunkHeader) {
	h.Type = header.Type
	h.Flags = header.Flags
	h.Length = header.Length
}

// Parse the supplied data as a sequence of SCTP Chunks
func readSCTPChunks(src io.Reader) ([]SCTPChunk, error) {
	chunks := make([]SCTPChunk, 0)

	var err error = nil

	// Parse the chunks one at a time until there is no data left
	for err != nil {

		// Parse the common header so we know the type and length of the chunk.
		header := SCTPChunkHeader{}
		err := header.ReadFrom(src)
		if err != nil {
			return nil, err
		}

		// The actual length of the chunk is always a multiple of 4
		actualLength := int64(header.Length + (4-(header.Length%4))%4)

		chunkReader := io.LimitReader(src, actualLength-int64(binary.Size(header)))

		// Parse this chunk.
		chunk, err := readSCTPChunk(&header, src)

		if err != nil && err != io.EOF {
			return nil, err
		}

		// Read any remaining data that the chunk didn't read.
		ioutil.ReadAll(chunkReader)

		chunks = append(chunks, chunk)
	}

	return chunks, nil
}

// Parse a single SCTP Chunk
func readSCTPChunk(header *SCTPChunkHeader, src io.Reader) (SCTPChunk, error) {
	var chunk SCTPChunk

	// Pick the correct chunk type.
	switch header.Type {
	case SCTP_CHUNK_DATA:
		chunk = new(SCTPChunkData)
	case SCTP_CHUNK_INIT:
		chunk = new(SCTPChunkInit)
	case SCTP_CHUNK_INIT_ACK:
		chunk = new(SCTPChunkInitAck)
	case SCTP_CHUNK_HEARTBEAT:
		chunk = new(SCTPChunkHeartbeat)
	case SCTP_CHUNK_HEARTBEAT_ACK:
		chunk = new(SCTPChunkHeartbeatAck)
	case SCTP_CHUNK_ABORT:
		chunk = new(SCTPChunkAbort)
	case SCTP_CHUNK_SHUTDOWN:
		chunk = new(SCTPChunkShutdown)
	case SCTP_CHUNK_SHUTDOWN_ACK:
		chunk = new(SCTPChunkShutdownAck)
	case SCTP_CHUNK_ERROR:
		chunk = new(SCTPChunkError)
	case SCTP_CHUNK_COOKIE_ECHO:
		chunk = new(SCTPChunkCookieEcho)
	case SCTP_CHUNK_COOKIE_ACK:
		chunk = new(SCTPChunkCookieAck)
	case SCTP_CHUNK_SHUTDOWN_COMPLETE:
		chunk = new(SCTPChunkShutdownComplete)
	default:
		chunk = new(SCTPChunkUnknown)
	}

	chunk.setHeader(header)

	err := chunk.readBodyFrom(src)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return chunk, err
}

//-----------------------------------------------------------------------------
// SCTPChunkUnknown
//-----------------------------------------------------------------------------

// SCTPChunkUnknown represents a chunk for a chunk type that we don't understand.  The data
// consists of all data after the chunk header.
type SCTPChunkUnknown struct {
	SCTPChunkHeader
	Data []byte
}

func (c *SCTPChunkUnknown) readBodyFrom(src io.Reader) error {
	var err error
	c.Data, err = ioutil.ReadAll(src)
	return err
}

//-----------------------------------------------------------------------------
// SCTPChunkData
//-----------------------------------------------------------------------------

// SCTPChunkData represents a DATA chunk in an SCTP Segment.
type SCTPChunkData struct {
	SCTPChunkHeader
	TSN                       uint32
	StreamIdentifier          uint16
	StreamSequenceNumber      uint16
	PayloadProtocolIdentifier uint32
	Data                      []byte
}

func (c *SCTPChunkData) readBodyFrom(src io.Reader) error {
	err := readFields(src, networkByteOrder, []interface{}{
		&c.TSN,
		&c.StreamIdentifier,
		&c.StreamSequenceNumber,
		&c.PayloadProtocolIdentifier,
	})

	c.Data = make([]byte, c.Length-uint16(binary.Size(c.SCTPChunkHeader)))
	_, err = src.Read(c.Data)

	return err
}

//-----------------------------------------------------------------------------
// SCTPChunkInit
//-----------------------------------------------------------------------------

// SCTPChunkInit represents an INIT chunk in an SCTP Segment.
type SCTPChunkInit struct {
	SCTPChunkHeader
	InitiateTag                    uint32
	AdvertisedReceiverWindowCredit uint32
	NumOutboundStreams             uint16
	NumInboundStreams              uint16
	InitialTSN                     uint32
	Parameters                     []SCTPChunkParameter
}

func (c *SCTPChunkInit) readBodyFrom(src io.Reader) error {
	// Read the fixed length fields.
	err := readFields(src, networkByteOrder, []interface{}{
		&c.InitiateTag,
		&c.AdvertisedReceiverWindowCredit,
		&c.NumOutboundStreams,
		&c.NumInboundStreams,
		&c.InitialTSN,
	})

	if err != nil {
		return err
	}

	// Parse the parameters.
	parameters, err := readSCTPChunkParameters(src, getSCTPInitChunkParameter)
	if err != nil {
		return err
	}

	c.Parameters = parameters

	return nil
}

func getSCTPInitChunkParameter(header *SCTPChunkParameterHeader) SCTPChunkParameter {
	var parameter SCTPChunkParameter

	// Pick the correct chunk type.
	switch header.Type {
	case SCTP_CHUNK_PARAMETER_IPV4_SENDER:
		parameter = new(SCTPChunkParameterIPv4Sender)
	case SCTP_CHUNK_PARAMETER_IPV6_SENDER:
		parameter = new(SCTPChunkParameterIPv6Sender)
	case SCTP_CHUNK_PARAMETER_COOKIE_LIFESPAN_INCREMENT:
		parameter = new(SCTPChunkParameterCookieLifespanInc)
	default:
		parameter = new(SCTPChunkParameterUnknown)
	}

	return parameter
}

//-----------------------------------------------------------------------------
// SCTPChunkInitAck
//-----------------------------------------------------------------------------

// SCTPChunkInit represents an INIT ACK chunk in an SCTP Segment.  The format of an INIT ACK
// chunk is the same as an INIT Chunk.
type SCTPChunkInitAck struct {
	SCTPChunkInit
}

//-----------------------------------------------------------------------------
// SCTPChunkSack
//-----------------------------------------------------------------------------

// SCTPChunkSack represents a SACK chunk in an SCTP Segment.
type SCTPChunkSack struct {
	SCTPChunkHeader
	CumulativeTSNACK               uint32
	AdvertisedReceivedWindowCredit uint32
	NumGapACKBlocks                uint16
	NumDuplicateTSNs               uint16
	GapACKBlocks                   []uint16 // Alternating start/end.  I should really break this out into a separate type.
	DuplicateTSNs                  []uint32
}

func (c *SCTPChunkSack) readBodyFrom(src io.Reader) error {
	// Read the fixed length fields.
	err := readFields(src, networkByteOrder, []interface{}{
		&c.CumulativeTSNACK,
		&c.AdvertisedReceivedWindowCredit,
		&c.NumGapACKBlocks,
		&c.NumDuplicateTSNs,
	})

	if err != nil {
		return err
	}

	// Read the arrays
	c.GapACKBlocks = make([]uint16, c.NumGapACKBlocks)
	c.DuplicateTSNs = make([]uint32, c.NumDuplicateTSNs)

	err = readFields(src, networkByteOrder, []interface{}{
		&c.GapACKBlocks,
		&c.DuplicateTSNs,
	})

	return err
}

//-----------------------------------------------------------------------------
// SCTPChunkHeartbeat
//-----------------------------------------------------------------------------

// SCTPChunkHeatbeat represents a HEARTBEAT chunk in an SCTP segment.
type SCTPChunkHeartbeat struct {
	SCTPChunkHeader
	Parameter SCTPChunkParameterHeartbeatInfo
}

func (c *SCTPChunkHeartbeat) readBodyFrom(src io.Reader) error {
	return c.Parameter.ReadFrom(src)
}

//-----------------------------------------------------------------------------
// SCTPChunkHeartbeatAck
//-----------------------------------------------------------------------------

// SCTPChunkHeartbeatAck represents a HEARTBEAT ACK chunk in an SCTP segment.  The format
// of a HEARTBEAT ACK chunk is the same as a HEARTBEAT chunk.
type SCTPChunkHeartbeatAck struct {
	SCTPChunkHeartbeat
}

//-----------------------------------------------------------------------------
// SCTPChunkAbort
//-----------------------------------------------------------------------------

// SCTPChunkAbort represents an ABORT chunk in an SCTP segment.
type SCTPChunkAbort struct {
	SCTPChunkHeader
	Errors uint32
}

func (c *SCTPChunkAbort) readBodyFrom(src io.Reader) error {
	return readFields(src, networkByteOrder, []interface{}{
		&c.Errors,
	})
}

//-----------------------------------------------------------------------------
// SCTPChunkShutdown
//-----------------------------------------------------------------------------

// SCTPChunkShutdown represents a SHUTDOWN chunk in an SCTP segment.
type SCTPChunkShutdown struct {
	SCTPChunkHeader
	CumulativeTSNACK uint32
}

func (c *SCTPChunkShutdown) readBodyFrom(src io.Reader) error {
	return readFields(src, networkByteOrder, []interface{}{
		&c.CumulativeTSNACK,
	})
}

//-----------------------------------------------------------------------------
// SCTPChunkShutdownAck
//-----------------------------------------------------------------------------

// SCTPChunkShutdownAck represents a SHUTDOWN ACK chunk in an SCTP segment.
type SCTPChunkShutdownAck struct {
	SCTPChunkHeader
}

//-----------------------------------------------------------------------------
// SCTPChunkError
//-----------------------------------------------------------------------------

// SCTPChunkError represents an ERROR chunk in an SCTP segment.
type SCTPChunkError struct {
	SCTPChunkHeader
	Parameters []SCTPChunkParameter
}

func (c *SCTPChunkError) readBodyFrom(src io.Reader) error {
	// Parse the parameters.
	var err error
	c.Parameters, err = readSCTPChunkParameters(src, getSCTPErrorChunkParameter)
	return err
}

func getSCTPErrorChunkParameter(header *SCTPChunkParameterHeader) SCTPChunkParameter {
	var parameter SCTPChunkParameter

	// Pick the correct chunk type.
	switch header.Type {
	default:
		parameter = new(SCTPChunkParameterUnknown)
	}

	return parameter
}

//-----------------------------------------------------------------------------
// SCTPChunkCookieEcho
//-----------------------------------------------------------------------------

// SCTPChunkCookieEcho represents a COOKIE ECHO chunk in an SCTP segment.
type SCTPChunkCookieEcho struct {
	SCTPChunkHeader
	Cookie []byte
}

func (c *SCTPChunkCookieEcho) readBodyFrom(src io.Reader) error {
	c.Cookie = make([]byte, c.Length-4)

	// Parse the cookie.
	_, err := src.Read(c.Cookie)

	return err
}

//-----------------------------------------------------------------------------
// SCTPChunkCookieAck
//-----------------------------------------------------------------------------

// SCTPChunkCookieAck represents a COOKIE ACK chunk in an SCTP segment.
type SCTPChunkCookieAck struct {
	SCTPChunkHeader
}

//-----------------------------------------------------------------------------
// SCTPChunkShutdownComplete
//-----------------------------------------------------------------------------

// SCTPChunkShutdownComplete represents a SHUTDOWN COMPLETE chunk in an SCTP segment.
type SCTPChunkShutdownComplete struct {
	SCTPChunkHeader
}
