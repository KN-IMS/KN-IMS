package collector

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// 프레임 헤더

const (
	FrameHeaderSize = 9 // 4(length) + 1(type) + 4(seq_num)
	MaxFrameSize    = 65535
)

// 메시지 Type

const (
	MsgRegister  uint8 = 0x01
	MsgHeartbeat uint8 = 0x02
	MsgFileEvent uint8 = 0x03
)

// 이벤트 Type

const (
	EvtCreate uint8 = 0x01
	EvtModify uint8 = 0x02
	EvtDelete uint8 = 0x03
	EvtAttrib uint8 = 0x04
	EvtMove   uint8 = 0x05
)

// 모니터 Type

const (
	MonLkm  uint8 = 0x02
	MonEbpf uint8 = 0x03
)

// agent 상태

const (
	StatusOnline  uint8 = 0x01
	StatusOffline uint8 = 0x02
	StatusHealthy uint8 = 0x03
	StatusWarning uint8 = 0x04
	StatusError   uint8 = 0x05
)

// 프레임 헤더 구조체

type FrameHeader struct {
	Length uint32
	Type   uint8
	SeqNum uint32
}

// 메시지 구조체

// RegisterMsg : 0x01 REGISTER Payload
type RegisterMsg struct {
	Hostname    string
	IP          net.IP
	MonitorType uint8
	OS          string
}

// RegisterResp : REGISTER ACK 응답 -> agent_id 반환
type RegisterResp struct {
	AgentID uint64
}

// HeartbeatMsg : 0x02 HEARTBEAT 페이로드 -> 13 bytes 고정
type HeartbeatMsg struct {
	AgentID   uint64
	Status    uint8
	Timestamp uint32
}

// FileEventMsg : 0x03 FILE_EVENT 페이로드
type FileEventMsg struct {
	AgentID        uint64
	EventType      uint8
	FilePath       string
	FileName       string
	FileHash       [32]byte
	FilePermission uint16
	DetectedBy     uint8
	Pid            uint32
	Timestamp      uint32
}

// 바이너리 읽기 헬퍼

type binReader struct {
	data []byte
	pos  int
}

func newBinReader(data []byte) *binReader {
	return &binReader{data: data}
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

func (r *binReader) readU16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, fmt.Errorf("버퍼 부족: u16")
	}
	v := binary.BigEndian.Uint16(r.data[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *binReader) readU32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, fmt.Errorf("버퍼 부족: u32")
	}
	v := binary.BigEndian.Uint32(r.data[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *binReader) readU64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, fmt.Errorf("버퍼 부족: u64")
	}
	hi := binary.BigEndian.Uint32(r.data[r.pos:])
	lo := binary.BigEndian.Uint32(r.data[r.pos+4:])
	r.pos += 8
	return (uint64(hi) << 32) | uint64(lo), nil
}

func (r *binReader) readStr() (string, error) {
	length, err := r.readU16()
	if err != nil {
		return "", err
	}
	if r.remaining() < int(length) {
		return "", fmt.Errorf("버퍼 부족: string(len=%d)", length)
	}
	s := string(r.data[r.pos : r.pos+int(length)])
	r.pos += int(length)
	return s, nil
}

func (r *binReader) readBytes(n int) ([]byte, error) {
	if r.remaining() < n {
		return nil, fmt.Errorf("버퍼 부족: bytes(%d)", n)
	}
	b := make([]byte, n)
	copy(b, r.data[r.pos:r.pos+n])
	r.pos += n
	return b, nil
}

// 바이너리 쓰기 헬퍼

type binWriter struct {
	buf []byte
}

func newBinWriter(capacity int) *binWriter {
	return &binWriter{buf: make([]byte, 0, capacity)}
}

func (w *binWriter) writeU8(v uint8) {
	w.buf = append(w.buf, v)
}

func (w *binWriter) writeU16(v uint16) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	w.buf = append(w.buf, b...)
}

func (w *binWriter) writeU32(v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	w.buf = append(w.buf, b...)
}

func (w *binWriter) writeU64(v uint64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[:4], uint32(v>>32))
	binary.BigEndian.PutUint32(b[4:], uint32(v&0xFFFFFFFF))
	w.buf = append(w.buf, b...)
}

func (w *binWriter) writeStr(s string) {
	w.writeU16(uint16(len(s)))
	w.buf = append(w.buf, []byte(s)...)
}

func (w *binWriter) writeBytes(data []byte) {
	w.buf = append(w.buf, data...)
}

func (w *binWriter) bytes() []byte {
	return w.buf
}

// 프레임 송수신

// ReadFrame : 프레임 수신
func ReadFrame(r io.Reader) (*FrameHeader, []byte, error) {
	hdrBuf := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(r, hdrBuf); err != nil {
		return nil, nil, fmt.Errorf("프레임 헤더 읽기 실패: %w", err)
	}

	hdr := &FrameHeader{
		Length: binary.BigEndian.Uint32(hdrBuf[:4]),
		Type:   hdrBuf[4],
		SeqNum: binary.BigEndian.Uint32(hdrBuf[5:9]),
	}

	if hdr.Length > MaxFrameSize {
		return nil, nil, fmt.Errorf("프레임 크기 초과: %d > %d", hdr.Length, MaxFrameSize)
	}

	var payload []byte
	if hdr.Length > 0 {
		payload = make([]byte, hdr.Length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, nil, fmt.Errorf("payload 읽기 실패: %w", err)
		}
	}

	return hdr, payload, nil
}

// WriteFrame : 프레임 전송
func WriteFrame(w io.Writer, msgType uint8, seqNum uint32, payload []byte) error {
	hdr := make([]byte, FrameHeaderSize)
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(payload)))
	hdr[4] = msgType
	binary.BigEndian.PutUint32(hdr[5:9], seqNum)

	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("헤더 전송 실패: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("payload 전송 실패: %w", err)
		}
	}
	return nil
}

// 디코딩

// DecodeRegister : 0x01 REGISTER 바이너리 -> RegisterMsg
func DecodeRegister(data []byte) (*RegisterMsg, error) {
	r := newBinReader(data)

	hostname, err := r.readStr()
	if err != nil {
		return nil, err
	}
	ipRaw, err := r.readU32()
	if err != nil {
		return nil, err
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipRaw)

	monType, err := r.readU8()
	if err != nil {
		return nil, err
	}
	osName, err := r.readStr()
	if err != nil {
		return nil, err
	}

	return &RegisterMsg{
		Hostname:    hostname,
		IP:          ip,
		MonitorType: monType,
		OS:          osName,
	}, nil
}

// DecodeHeartbeat : 0x02 HEARTBEAT 바이너리 -> HeartbeatMsg
func DecodeHeartbeat(data []byte) (*HeartbeatMsg, error) {
	if len(data) < 13 {
		return nil, fmt.Errorf("HEARTBEAT 크기 부족: %d", len(data))
	}
	r := newBinReader(data)
	agentID, _ := r.readU64()
	status, _ := r.readU8()
	timestamp, _ := r.readU32()

	return &HeartbeatMsg{
		AgentID:   agentID,
		Status:    status,
		Timestamp: timestamp,
	}, nil
}

// DecodeFileEvent : 0x03 FILE_EVENT 바이너리 -> FileEventMsg
func DecodeFileEvent(data []byte) (*FileEventMsg, error) {
	r := newBinReader(data)

	agentID, err := r.readU64()
	if err != nil {
		return nil, err
	}
	evtType, err := r.readU8()
	if err != nil {
		return nil, err
	}
	filePath, err := r.readStr()
	if err != nil {
		return nil, err
	}
	fileName, err := r.readStr()
	if err != nil {
		return nil, err
	}
	hashBytes, err := r.readBytes(32)
	if err != nil {
		return nil, err
	}
	perm, err := r.readU16()
	if err != nil {
		return nil, err
	}
	detectedBy, err := r.readU8()
	if err != nil {
		return nil, err
	}
	pid, err := r.readU32()
	if err != nil {
		return nil, err
	}
	timestamp, err := r.readU32()
	if err != nil {
		return nil, err
	}

	msg := &FileEventMsg{
		AgentID:        agentID,
		EventType:      evtType,
		FilePath:       filePath,
		FileName:       fileName,
		FilePermission: perm,
		DetectedBy:     detectedBy,
		Pid:            pid,
		Timestamp:      timestamp,
	}
	copy(msg.FileHash[:], hashBytes)
	return msg, nil
}

// 인코딩

// EncodeRegisterResp : agent_id -> REGISTER ACK 바이너리
func EncodeRegisterResp(agentID uint64) []byte {
	w := newBinWriter(8)
	w.writeU64(agentID)
	return w.bytes()
}

// 문자열 변환

// EventTypeName : 이벤트 Type uint8 -> 문자열
func EventTypeName(t uint8) string {
	switch t {
	case EvtCreate:
		return "CREATE"
	case EvtModify:
		return "MODIFY"
	case EvtDelete:
		return "DELETE"
	case EvtAttrib:
		return "ATTRIB"
	case EvtMove:
		return "MOVE"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", t)
	}
}

// MonitorTypeName : 모니터 Type uint8 -> 문자열
func MonitorTypeName(t uint8) string {
	switch t {
	case MonLkm:
		return "lkm"
	case MonEbpf:
		return "ebpf"
	default:
		return fmt.Sprintf("unknown(0x%02x)", t)
	}
}

// StatusName : agent 상태 uint8 -> 문자열
func StatusName(t uint8) string {
	switch t {
	case StatusOnline:
		return "ONLINE"
	case StatusOffline:
		return "OFFLINE"
	case StatusHealthy:
		return "HEALTHY"
	case StatusWarning:
		return "WARNING"
	case StatusError:
		return "ERROR"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", t)
	}
}

// PermString : 파일 권한 uint16 -> "0644" 형식 문자열
func PermString(perm uint16) string {
	return fmt.Sprintf("%04o", perm)
}

// GenerateAgentID : hostname + IP 해시 -> uint64 agent_id
func GenerateAgentID(hostname string, ip net.IP) uint64 {
	h := uint64(0)
	for _, c := range hostname {
		h = h*31 + uint64(c)
	}
	ip4 := ip.To4()
	if ip4 != nil {
		h = h*31 + uint64(binary.BigEndian.Uint32(ip4))
	}
	if h == 0 {
		h = 1
	}
	return h
}
