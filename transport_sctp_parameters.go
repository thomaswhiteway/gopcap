package gopcap

import (
	"encoding/binary"
	"io"
	"io/ioutil"
)

// Parse the supplied data as a sequence of SCTP Chunk parameters
func readSCTPChunkParameters(src io.Reader, getParameter SCTPChunkParameterFactory) ([]SCTPChunkParameter, error) {
	parameters := make([]SCTPChunkParameter, 0)

	var err error = nil

	// Parse the parameters one at a time until there is no data left
	for err != nil {

		// Parse the common header so we know the type and length of the parameter.
		header := SCTPChunkParameterHeader{}
		err := header.ReadFrom(src)
		if err != nil {
			return nil, err
		}

		chunkReader := io.LimitReader(src, int64(header.Length)-int64(binary.Size(header)))

		// Parse this chunk.
		parameter := getParameter(&header)
		parameter.setHeader(&header)
		err = parameter.readBodyFrom(src)
		if err != nil && err != io.EOF {
			return nil, err
		}

		// Read any remaining data that the chunk didn't read.
		ioutil.ReadAll(chunkReader)

		parameters = append(parameters, parameter)
	}

	return parameters, nil
}

// Function type for building an SCTP Chunk parameter.
type SCTPChunkParameterFactory func(header *SCTPChunkParameterHeader) SCTPChunkParameter

// SCTPChunkParameter represents a single parameter in and SCTP Chunk
type SCTPChunkParameter interface {
	ParameterType() SCTPChunkParameterType
	ParameterLength() uint16
	ReadFrom(src io.Reader) error
	readBodyFrom(src io.Reader) error
	setHeader(header *SCTPChunkParameterHeader)
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

func (h *SCTPChunkParameterHeader) ReadFrom(src io.Reader) error {
	err := readFields(src, networkByteOrder, []interface{}{
		&h.Type,
		&h.Length,
	})
	if err != nil {
		return err
	}
	return h.readBodyFrom(src)
}

func (h *SCTPChunkParameterHeader) readBodyFrom(rc io.Reader) error {
	return nil
}

func (h *SCTPChunkParameterHeader) setHeader(header *SCTPChunkParameterHeader) {
	h.Type = header.Type
	h.Length = header.Length
}

// SCTPChunkParameterUnknown represents a parameter for a parameter we don't understand.  The data
// consists of all data after the header.
type SCTPChunkParameterUnknown struct {
	SCTPChunkParameterHeader
	Data []byte
}

func (p *SCTPChunkParameterUnknown) readBodyFrom(src io.Reader) error {
	p.Data = make([]byte, p.Length-uint16(binary.Size(p.SCTPChunkParameterHeader)))
	_, err := src.Read(p.Data)
	return err
}

// SCTPChunkParameterIPv4Sender represents the parameter in an SCTP INIT chunk containing the IPv4
// address of the sending endpoint.
type SCTPChunkParameterIPv4Sender struct {
	SCTPChunkParameterHeader
	Address [4]byte
}

func (p *SCTPChunkParameterIPv4Sender) readBodyFrom(src io.Reader) error {
	return readFields(src, networkByteOrder, []interface{}{
		&p.Address,
	})
}

// SCTPChunkParameterIPv6Sender represents the parameter in an SCTP INIT chunk containing the IPv6
// address of the sending endpoint.
type SCTPChunkParameterIPv6Sender struct {
	SCTPChunkParameterHeader
	Address [16]byte
}

func (p *SCTPChunkParameterIPv6Sender) readBodyFrom(src io.Reader) error {
	return readFields(src, networkByteOrder, []interface{}{
		&p.Address,
	})
}

// SCTPChunkParameterCookieLifespanInc represents the parameter in an SCTP INIT chunk containing the
// suggested cookie lifespan increment.
type SCTPChunkParameterCookieLifespanInc struct {
	SCTPChunkParameterHeader
	Increment uint32
}

func (p *SCTPChunkParameterCookieLifespanInc) readBodyFrom(src io.Reader) error {
	return readFields(src, networkByteOrder, []interface{}{
		&p.Increment,
	})
}

// SCTPChunkParameterHeartbeatInfo represents the parameter in a HEARTBEAT or HEARTBEAT ACK
// chunk.
type SCTPChunkParameterHeartbeatInfo struct {
	SCTPChunkParameterHeader
	Info []byte
}

func (p *SCTPChunkParameterHeartbeatInfo) readBodyFrom(src io.Reader) error {
	p.Info = make([]byte, p.Length-uint16(binary.Size(p.SCTPChunkParameterHeader)))
	_, err := src.Read(p.Info)
	return err
}

// TODO: Add support for the remaining parameter types.
