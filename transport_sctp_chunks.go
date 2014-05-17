package gopcap

// SCTPChunk represents a single SCTP Chunk in an SCTP Segment.
type SCTPChunk interface {
	ChunkType() SCTPChunkType
	ChunkFlags() uint8
	ChunkLength() uint16
	FromBytes(data []byte) error
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

func (h *SCTPChunkHeader) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the header.
	if len(data) < 4 {
		return InsufficientLength
	}

	// Parse the individual fields
	h.Type = SCTPChunkType(data[0])
	h.Flags = data[1]
	h.Length = getUint16(data[2:4], false)

	return nil
}

// SCTPChunkUnknown represents a chunk for a chunk type that we don't understand.  The data
// consists of all data after the chunk header.
type SCTPChunkUnknown struct {
	SCTPChunkHeader
	Data []byte
}

func (c *SCTPChunkUnknown) FromBytes(data []byte) error {
	// Parse the common header
	err := c.SCTPChunkHeader.FromBytes(data)
	if err != nil {
		return err
	}

	// The data is the rest of the message
	c.Data = data[4:]

	return nil
}

// SCTPChunkData represents a DATA chunk in an SCTP Segment.
type SCTPChunkData struct {
	SCTPChunkHeader
	TSN                       uint32
	StreamIdentifier          uint16
	StreamSequenceNumber      uint16
	PayloadProtocolIdentifier uint32
	Data                      []byte
}

func (c *SCTPChunkData) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 16 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that this data is for a DATA chunk.
	if c.Type != 0 {
		return IncorrectPacket
	}

	// Parse the fixed length fields
	c.TSN = getUint32(data[4:8], false)
	c.StreamIdentifier = getUint16(data[8:10], false)
	c.StreamSequenceNumber = getUint16(data[10:12], false)
	c.PayloadProtocolIdentifier = getUint32(data[12:16], false)

	// The data is the remaining bytes.
	c.Data = data[16:]

	return nil
}

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

func (c *SCTPChunkInit) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 20 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that this data is for an INIT or INIT_ACK chunk.
	if c.Type != 1 && c.Type != 2 {
		return IncorrectPacket
	}

	// Parse the fixed length fields.
	c.InitiateTag = getUint32(data[4:8], false)
	c.AdvertisedReceiverWindowCredit = getUint32(data[8:12], false)
	c.NumOutboundStreams = getUint16(data[12:14], false)
	c.NumInboundStreams = getUint16(data[14:16], false)
	c.InitialTSN = getUint32(data[16:20], false)

	// Parse the parameters.
	parameters, err := parseSCTPChunkParameters(data[20:c.Length], parseSCTPInitChunkParameter)
	if err != nil {
		return err
	}

	c.Parameters = parameters

	return nil
}

func parseSCTPInitChunkParameter(header *SCTPChunkParameterHeader, data []byte) (SCTPChunkParameter, error) {
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

	// Parse the paramter.  It's not ideal that end up parsing the header twice but it makes the
	// API for parsing the parameters cleaner if we don't have to cope with parsing only part of
	// the parameter.
	err := parameter.FromBytes(data)
	if err != nil {
		return nil, err
	}

	return parameter, nil
}

// SCTPChunkInit represents an INIT ACK chunk in an SCTP Segment.  The format of an INIT ACK
// chunk is the same as an INIT Chunk.
type SCTPChunkInitAck SCTPChunkInit

// SCTPChunkInit represents a SACK chunk in an SCTP Segment.
type SCTPChunkSack struct {
	SCTPChunkHeader
	CumulativeTSNACK               uint32
	AdvertisedReceivedWindowCredit uint32
	NumGapACKBlocks                uint16
	NumDuplicateTSNs               uint16
	GapACKBlocks                   []uint16 // Alternating start/end.  I should really break this out into a separate type.
	DuplicateTSNs                  []uint32
}

func (c *SCTPChunkSack) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 16 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that the data is for a SACK chunk.
	if c.Type != 3 {
		return IncorrectPacket
	}

	// Parse the fixed length fields
	c.CumulativeTSNACK = getUint32(data[4:8], false)
	c.AdvertisedReceivedWindowCredit = getUint32(data[8:12], false)
	c.NumGapACKBlocks = getUint16(data[12:14], false)
	c.NumDuplicateTSNs = getUint16(data[14:16], false)

	if uint16(len(data)) < 16+4*c.NumGapACKBlocks+4*c.NumDuplicateTSNs {
		return InsufficientLength
	}

	offset := 16

	c.GapACKBlocks = make([]uint16, c.NumGapACKBlocks)
	for idx := uint16(0); idx < c.NumGapACKBlocks*2; idx++ {
		c.GapACKBlocks[uint16(idx)] = getUint16(data[offset:offset+2], false)
		offset += 2
	}

	c.DuplicateTSNs = make([]uint32, c.NumDuplicateTSNs)
	for idx := uint16(0); idx < c.NumDuplicateTSNs; idx++ {
		c.DuplicateTSNs[idx] = getUint32(data[offset:offset+4], false)
		offset += 4
	}

	return nil
}

// SCTPChunkHeatbeat represents a HEARTBEAT chunk in an SCTP segment.
type SCTPChunkHeartbeat struct {
	SCTPChunkHeader
	Parameter SCTPChunkParameterHeartbeatInfo
}

func (c *SCTPChunkHeartbeat) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 4 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that the packet is for a HEARTBEAT or HEARTBEAT ACK chunk.
	if c.Type != SCTP_CHUNK_HEARTBEAT && c.Type != SCTP_CHUNK_HEARTBEAT_ACK {
		return IncorrectPacket
	}

	// Parse the parameter
	err = c.Parameter.FromBytes(data[4:c.Length])
	if err != nil {
		return err
	}

	return nil
}

// SCTPChunkHeartbeatAck represents a HEARTBEAT ACK chunk in an SCTP segment.  The format
// of a HEARTBEAT ACK chunk is the same as a HEARTBEAT chunk.
type SCTPChunkHeartbeatAck SCTPChunkHeartbeat

// SCTPChunkAbort represents an ABORT chunk in an SCTP segment.
type SCTPChunkAbort struct {
	SCTPChunkHeader
	Errors uint32
}

func (c *SCTPChunkAbort) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 8 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that the packet is for an ABORT chunk.
	if c.Type != SCTP_CHUNK_ABORT {
		return IncorrectPacket
	}

	// Parse the errors
	c.Errors = getUint32(data[4:8], false)

	return nil
}

// SCTPChunkShutdown represents a SHUTDOWN chunk in an SCTP segment.
type SCTPChunkShutdown struct {
	SCTPChunkHeader
	CumulativeTSNACK uint32
}

func (c *SCTPChunkShutdown) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 8 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that the packet is for a SHUTDOWN chunk.
	if c.Type != SCTP_CHUNK_SHUTDOWN {
		return IncorrectPacket
	}

	// Parse the errors
	c.CumulativeTSNACK = getUint32(data[4:8], false)

	return nil
}

// SCTPChunkShutdownAck represents a SHUTDOWN ACK chunk in an SCTP segment.
type SCTPChunkShutdownAck struct {
	SCTPChunkHeader
}

func (c *SCTPChunkShutdownAck) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 4 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that the packet is for a SHUTDOWN ACK chunk.
	if c.Type != SCTP_CHUNK_SHUTDOWN_ACK {
		return IncorrectPacket
	}

	return nil
}

// SCTPChunkError represents an ERROR chunk in an SCTP segment.
type SCTPChunkError struct {
	SCTPChunkHeader
	Parameters []SCTPChunkParameter
}

func (c *SCTPChunkError) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 4 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that the packet is for an ERROR chunk.
	if c.Type != SCTP_CHUNK_ERROR {
		return IncorrectPacket
	}

	// Parse the parameters.
	parameters, err := parseSCTPChunkParameters(data[4:c.Length], parseSCTPErrorChunkParameter)
	if err != nil {
		return err
	}

	c.Parameters = parameters

	return nil
}

func parseSCTPErrorChunkParameter(header *SCTPChunkParameterHeader, data []byte) (SCTPChunkParameter, error) {
	var parameter SCTPChunkParameter

	// Pick the correct chunk type.
	switch header.Type {
	default:
		parameter = new(SCTPChunkParameterUnknown)
	}

	// Parse the paramter.  It's not ideal that end up parsing the header twice but it makes the
	// API for parsing the parameters cleaner if we don't have to cope with parsing only part of
	// the parameter.
	err := parameter.FromBytes(data)
	if err != nil {
		return nil, err
	}

	return parameter, nil
}

// SCTPChunkCookieEcho represents a COOKIE ECHO chunk in an SCTP segment.
type SCTPChunkCookieEcho struct {
	SCTPChunkHeader
	Cookie []byte
}

func (c *SCTPChunkCookieEcho) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 4 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that the packet is for a SHUTDOWN ACK chunk.
	if c.Type != SCTP_CHUNK_COOKIE_ECHO {
		return IncorrectPacket
	}

	// Check there's enough data for the cookie.
	if uint16(len(data)) < c.Length {
		return InsufficientLength
	}

	// Parse the cookie.
	c.Cookie = data[4:c.Length]

	return nil
}

// SCTPChunkCookieAck represents a COOKIE ACK chunk in an SCTP segment.
type SCTPChunkCookieAck struct {
	SCTPChunkHeader
}

func (c *SCTPChunkCookieAck) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 4 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that the packet is for a COOKIE ACK chunk.
	if c.Type != SCTP_CHUNK_COOKIE_ACK {
		return IncorrectPacket
	}

	return nil
}

// SCTPChunkShutdownComplete represents a SHUTDOWN COMPLETE chunk in an SCTP segment.
type SCTPChunkShutdownComplete struct {
	SCTPChunkHeader
}

func (c *SCTPChunkShutdownComplete) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the chunk.
	if len(data) < 4 {
		return InsufficientLength
	}

	// Parse the common header.
	err := c.SCTPChunkHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that the packet is for a SHUTDOWN COMPLETE chunk.
	if c.Type != SCTP_CHUNK_SHUTDOWN_COMPLETE {
		return IncorrectPacket
	}

	return nil
}

// Parse the supplied data as a sequence of SCTP Chunks
func parseSCTPChunks(data []byte) ([]SCTPChunk, error) {
	chunks := make([]SCTPChunk, 0)

	// Parse the chunks one at a time until there is no data left
	for len(data) > 0 {

		// Parse the common header so we know the type and length of the chunk.
		header := SCTPChunkHeader{}
		err := header.FromBytes(data)
		if err != nil {
			return nil, err
		}

		// The actual length of the chunk is always a multiple of 4
		actualLength := header.Length + (4-(header.Length%4))%4

		if len(data) < int(actualLength) {
			return nil, InsufficientLength
		}

		// Split out the data for this chunk from the data for the remaining chunks.
		chunkData := data[:actualLength]
		data = data[actualLength:]

		// Parse this chunk.
		chunk, err := parseSCTPChunk(&header, chunkData)
		if err != nil {
			return nil, err
		}

		chunks = append(chunks, chunk)
	}

	return chunks, nil
}

// Parse a single SCTP Chunk
func parseSCTPChunk(header *SCTPChunkHeader, data []byte) (SCTPChunk, error) {
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

	// Parse the chunk.  It's not ideal that end up parsing the header twice but it makes the API
	// for parsing the chunks cleaner if we don't have to cope with parsing only part of the chunk.
	err := chunk.FromBytes(data)
	if err != nil {
		return nil, err
	}

	return chunk, nil
}
