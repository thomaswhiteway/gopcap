package gopcap

// Parse the supplied data as a sequence of SCTP Chunk parameters
func parseSCTPChunkParameters(data []byte, parseParameter SCTPChunkParameterParser) ([]SCTPChunkParameter, error) {
	parameters := make([]SCTPChunkParameter, 0)

	// Parse the parameters one at a time until there is no data left
	for len(data) > 0 {

		// Parse the common header so we know the type and length of the parameter.
		header := SCTPChunkParameterHeader{}
		err := header.FromBytes(data)
		if err != nil {
			return nil, err
		}

		if len(data) < int(header.Length) {
			return nil, InsufficientLength
		}

		// Split out the data for this parameter from the data for the remaining parameters.
		parameterData := data[:header.Length]
		data = data[header.Length:]

		// Parse this chunk.
		parameter, err := parseParameter(&header, parameterData)
		if err != nil {
			return nil, err
		}

		parameters = append(parameters, parameter)
	}

	return parameters, nil
}

// Function type for parsing an SCTP Chunk parameter.
type SCTPChunkParameterParser func(header *SCTPChunkParameterHeader, data []byte) (SCTPChunkParameter, error)

// SCTPChunkParameter represents a single parameter in and SCTP Chunk
type SCTPChunkParameter interface {
	ParameterType() SCTPChunkParameterType
	ParameterLength() uint16
	FromBytes(data []byte) error
}

// The common header for parameters in SCTP Chunks.
type SCTPChunkParameterHeader struct {
	Type   SCTPChunkParameterType
	Length uint16
}

func (h *SCTPChunkParameterHeader) ParameterType() SCTPChunkParameterType {
	return h.Type
}

func (h *SCTPChunkParameterHeader) ParameterLength() uint16 {
	return h.Length
}

func (h *SCTPChunkParameterHeader) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the parameter.
	if len(data) < 4 {
		return InsufficientLength
	}

	// Parse the fields.
	h.Type = SCTPChunkParameterType(getUint16(data[0:2], false))
	h.Length = getUint16(data[2:4], false)

	return nil
}

// SCTPChunkParameterUnknown represents a parameter for a parameter we don't understand.  The data
// consists of all data after the header.
type SCTPChunkParameterUnknown struct {
	SCTPChunkParameterHeader
	Data []byte
}

func (p *SCTPChunkParameterUnknown) FromBytes(data []byte) error {
	// Parse the common header.
	err := p.SCTPChunkParameterHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Parse the remaining data.
	p.Data = data[4:]

	return nil
}

// SCTPChunkParameterIPv4Sender represents the parameter in an SCTP INIT chunk containing the IPv4
// address of the sending endpoint.
type SCTPChunkParameterIPv4Sender struct {
	SCTPChunkParameterHeader
	Address []byte
}

func (p *SCTPChunkParameterIPv4Sender) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the parameter.
	if len(data) < 8 {
		return InsufficientLength
	}

	// Parse the common header.
	err := p.SCTPChunkParameterHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that this data is for an IPv4 Sender parameter
	if p.Type != 5 {
		return IncorrectPacket
	}

	// Parse the address.
	p.Address = data[4:8]

	return nil
}

// SCTPChunkParameterIPv6Sender represents the parameter in an SCTP INIT chunk containing the IPv6
// address of the sending endpoint.
type SCTPChunkParameterIPv6Sender struct {
	SCTPChunkParameterHeader
	Address []byte
}

func (p *SCTPChunkParameterIPv6Sender) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the parameter.
	if len(data) < 20 {
		return InsufficientLength
	}

	// Parse the common header.
	err := p.SCTPChunkParameterHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that this data is for an IPv6 Sender parameter
	if p.Type != 6 {
		return IncorrectPacket
	}

	// Parse the address.
	p.Address = data[4:20]

	return nil
}

// SCTPChunkParameterCookieLifespanInc represents the parameter in an SCTP INIT chunk containing the
// suggested cookie lifespan increment.
type SCTPChunkParameterCookieLifespanInc struct {
	SCTPChunkParameterHeader
	Increment uint32
}

func (p *SCTPChunkParameterCookieLifespanInc) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the parameter.
	if len(data) < 8 {
		return InsufficientLength
	}

	// Parse the common header.
	err := p.SCTPChunkParameterHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that this data is for a suggested cookie life span increment parameter.
	if p.Type != 9 {
		return IncorrectPacket
	}

	// Parse the increment
	p.Increment = getUint32(data[4:8], false)

	return nil
}

// SCTPChunkParameterHeartbeatInfo represents the parameter in a HEARTBEAT or HEARTBEAT ACK
// chunk.
type SCTPChunkParameterHeartbeatInfo struct {
	SCTPChunkParameterHeader
	Info []byte
}

func (p *SCTPChunkParameterHeartbeatInfo) FromBytes(data []byte) error {
	// Begin by confirming we have enough data for the parameter.
	if len(data) < 4 {
		return InsufficientLength
	}

	// Parse the common header.
	err := p.SCTPChunkParameterHeader.FromBytes(data[:4])
	if err != nil {
		return err
	}

	// Ensure that this data is for a heartbeat info parameter.
	if p.Type != SCTP_CHUNK_PARAMETER_HEARTBEAT_INFO {
		return IncorrectPacket
	}

	// Check that there's enough data
	if uint16(len(data)) < 4+p.Length {
		return InsufficientLength
	}

	// Extract the remaining data
	p.Info = data[4 : 4+p.Length]

	return nil
}

// TODO: Add support for the remaining parameter types.
