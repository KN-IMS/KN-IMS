package enrollment

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	frameHeaderSize = 9
	maxFrameSize    = 65535

	MsgXORHello          uint8 = 0x21
	MsgXORChallenge      uint8 = 0x22
	MsgXOREnrollRequest  uint8 = 0x23
	MsgXOREnrollResponse uint8 = 0x24
	MsgXOREnrollAck      uint8 = 0x25
	MsgXOREnrollError    uint8 = 0x26
)

// Hello : 보호 채널 시작 전 공개 handshake payload
type Hello struct {
	EnrollmentID string
	ClientNonce  []byte
}

// Challenge : Backend가 보낸 nonce + key possession proof
type Challenge struct {
	ServerNonce []byte
	Proof       []byte
}

// Request : XOR protected Agent enrollment 요청 payload
type Request struct {
	Hostname    string
	IP          string
	OS          string
	MonitorType uint8
}

// Response : Agent enrollment 응답 payload
type Response struct {
	AgentID      string
	AgentCertPEM []byte
	AgentKeyPEM  []byte
	CACertPEM    []byte
	ExpiresAt    time.Time
}

type frameHeader struct {
	length uint32
	msgTyp uint8
	seqNum uint32
}

type binReader struct {
	data []byte
	pos  int
}

type binWriter struct {
	buf []byte
}

func readFrame(r io.Reader) (frameHeader, []byte, error) {
	hdrBuf := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(r, hdrBuf); err != nil {
		return frameHeader{}, nil, err
	}
	hdr := frameHeader{
		length: binary.BigEndian.Uint32(hdrBuf[0:4]),
		msgTyp: hdrBuf[4],
		seqNum: binary.BigEndian.Uint32(hdrBuf[5:9]),
	}
	if hdr.length > maxFrameSize {
		return frameHeader{}, nil, fmt.Errorf("frame length 초과: %d", hdr.length)
	}
	payloadLen := int(hdr.length) - frameHeaderSize
	if payloadLen < 0 {
		return frameHeader{}, nil, fmt.Errorf("잘못된 frame length: %d", hdr.length)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return frameHeader{}, nil, err
	}
	return hdr, payload, nil
}

func writeFrame(w io.Writer, msgTyp uint8, seqNum uint32, payload []byte) error {
	if len(payload)+frameHeaderSize > maxFrameSize {
		return fmt.Errorf("payload length 초과: %d", len(payload))
	}
	hdr := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(payload)+frameHeaderSize))
	hdr[4] = msgTyp
	binary.BigEndian.PutUint32(hdr[5:9], seqNum)
	if err := writeAll(w, hdr); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func decodeHello(payload []byte) (Hello, error) {
	r := &binReader{data: payload}
	enrollmentID, err := r.readString()
	if err != nil {
		return Hello{}, err
	}
	clientNonce, err := r.readBytes()
	if err != nil {
		return Hello{}, err
	}
	if r.remaining() != 0 {
		return Hello{}, fmt.Errorf("enrollment hello trailing bytes: %d", r.remaining())
	}
	if enrollmentID == "" || len(clientNonce) != nonceSize {
		return Hello{}, fmt.Errorf("invalid enrollment hello")
	}
	return Hello{EnrollmentID: enrollmentID, ClientNonce: clientNonce}, nil
}

func encodeChallenge(ch Challenge) ([]byte, error) {
	w := newBinWriter(2 + len(ch.ServerNonce) + 2 + len(ch.Proof))
	if err := w.writeBytes(ch.ServerNonce); err != nil {
		return nil, err
	}
	if err := w.writeBytes(ch.Proof); err != nil {
		return nil, err
	}
	return w.buf, nil
}

func decodeRequest(payload []byte) (Request, error) {
	r := &binReader{data: payload}
	hostname, err := r.readString()
	if err != nil {
		return Request{}, err
	}
	ip, err := r.readString()
	if err != nil {
		return Request{}, err
	}
	osName, err := r.readString()
	if err != nil {
		return Request{}, err
	}
	monitorType, err := r.readU8()
	if err != nil {
		return Request{}, err
	}
	if r.remaining() != 0 {
		return Request{}, fmt.Errorf("enrollment request trailing bytes: %d", r.remaining())
	}
	return Request{
		Hostname:    hostname,
		IP:          ip,
		OS:          osName,
		MonitorType: monitorType,
	}, nil
}

func encodeResponse(resp Response) ([]byte, error) {
	w := newBinWriter(512 + len(resp.AgentCertPEM) + len(resp.CACertPEM))
	if err := w.writeString(resp.AgentID); err != nil {
		return nil, err
	}
	if err := w.writeString(string(resp.AgentCertPEM)); err != nil {
		return nil, err
	}
	if err := w.writeString(string(resp.AgentKeyPEM)); err != nil {
		return nil, err
	}
	if err := w.writeString(string(resp.CACertPEM)); err != nil {
		return nil, err
	}
	w.writeU64(uint64(resp.ExpiresAt.Unix()))
	return w.buf, nil
}

func encodeError(message string) ([]byte, error) {
	w := newBinWriter(len(message) + 2)
	if err := w.writeString(message); err != nil {
		return nil, err
	}
	return w.buf, nil
}

func (r *binReader) remaining() int {
	return len(r.data) - r.pos
}

func (r *binReader) readU8() (uint8, error) {
	if r.remaining() < 1 {
		return 0, fmt.Errorf("버퍼 부족: u8")
	}
	v := r.data[r.pos]
	r.pos++
	return v, nil
}

func (r *binReader) readString() (string, error) {
	if r.remaining() < 2 {
		return "", fmt.Errorf("버퍼 부족: string length")
	}
	length := int(binary.BigEndian.Uint16(r.data[r.pos : r.pos+2]))
	r.pos += 2
	if r.remaining() < length {
		return "", fmt.Errorf("버퍼 부족: string(%d)", length)
	}
	s := string(r.data[r.pos : r.pos+length])
	r.pos += length
	return s, nil
}

func (r *binReader) readBytes() ([]byte, error) {
	if r.remaining() < 2 {
		return nil, fmt.Errorf("버퍼 부족: bytes length")
	}
	length := int(binary.BigEndian.Uint16(r.data[r.pos : r.pos+2]))
	r.pos += 2
	if r.remaining() < length {
		return nil, fmt.Errorf("버퍼 부족: bytes(%d)", length)
	}
	b := make([]byte, length)
	copy(b, r.data[r.pos:r.pos+length])
	r.pos += length
	return b, nil
}

func newBinWriter(capacity int) *binWriter {
	return &binWriter{buf: make([]byte, 0, capacity)}
}

func (w *binWriter) writeString(s string) error {
	if len(s) > 65535 {
		return fmt.Errorf("string length 초과: %d", len(s))
	}
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	w.buf = append(w.buf, b...)
	w.buf = append(w.buf, []byte(s)...)
	return nil
}

func (w *binWriter) writeBytes(data []byte) error {
	if len(data) > 65535 {
		return fmt.Errorf("bytes length 초과: %d", len(data))
	}
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(data)))
	w.buf = append(w.buf, b...)
	w.buf = append(w.buf, data...)
	return nil
}

func (w *binWriter) writeU64(v uint64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	w.buf = append(w.buf, b...)
}
