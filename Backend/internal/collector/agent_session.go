package collector

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// AgentSession : 연결된 에이전트 1개의 생명주기 관리 -> goroutine으로 병렬 처리
type AgentSession struct {
	AgentID  string // uint64 -> 문자열로 변환하여 저장
	agentNum uint64 // 바이너리 프로토콜의 agent_id (uint64)
	ctx      context.Context
	cancel   context.CancelFunc
	conn     *tls.Conn
	agents   internal.AgentStore
	events   internal.EventStore
	alerts   internal.AlertStore
	pub      internal.EventPublisher
	onEvent  func(ctx context.Context, agentID string, e internal.FileEvent)
	sessions *sync.Map // 서버의 세션 맵 참조 -> 중복 연결 처리 + 검증
	lastSeq  uint32    // seq_num 검증
}

// Run : 메시지 수신 루프 -> 연결 종료까지 실행
func (s *AgentSession) Run() {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	// 연결 끊겼을 때 ctx 취소
	defer func() {
		s.cancel()
		isCurrentSession := false
		if s.agentNum > 0 && s.sessions != nil && s.AgentID != "" {
			if current, ok := s.sessions.Load(s.AgentID); ok && current == s.conn {
				s.sessions.Delete(s.AgentID)
				isCurrentSession = true
			}
		}
		if s.AgentID != "" && isCurrentSession {
			// 현재 활성 세션이 끊기는 경우에만 offline 처리
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cleanupCancel()
			if err := s.agents.SetOffline(cleanupCtx, s.AgentID); err != nil {
				slog.Warn("SetOffline 실패", "agent_id", s.AgentID, "err", err)
			}
		}
		s.conn.Close()
	}()

	for {
		hdr, payload, err := ReadFrame(s.conn)
		if err != nil {
			slog.Info("연결 종료", "agent_id", s.AgentID, "err", err)
			return
		}

		// seq_num 검증 -> 불일치 시 연결 끊음
		if s.lastSeq > 0 && hdr.SeqNum != s.lastSeq+1 {
			slog.Warn("seq_num 불일치 -> 연결 끊음", "agent_id", s.AgentID, "expected", s.lastSeq+1, "got", hdr.SeqNum)
			return
		}
		s.lastSeq = hdr.SeqNum

		switch hdr.Type {
		case MsgRegister:
			s.handleRegister(hdr, payload)
		case MsgHeartbeat:
			s.handleHeartbeat(payload)
		case MsgFileEvent:
			s.handleFileEvent(payload)
		default:
			slog.Warn("알 수 없는 메시지 타입",
				"type", fmt.Sprintf("0x%02x", hdr.Type),
				"seq", hdr.SeqNum)
		}
	}
}

// handleRegister : 0x01 REGISTER -> agent_id 생성 + DB 저장 + ACK 응답
func (s *AgentSession) handleRegister(hdr *FrameHeader, payload []byte) {
	reg, err := DecodeRegister(payload)
	if err != nil {
		slog.Error("REGISTER 디코딩 실패", "err", err)
		return
	}

	s.agentNum = GenerateAgentID(reg.Hostname, reg.IP)
	s.AgentID = strconv.FormatUint(s.agentNum, 10)

	// 중복 연결 처리 -> 기존 연결 종료
	if s.sessions != nil {
		if old, loaded := s.sessions.LoadAndDelete(s.AgentID); loaded {
			slog.Info("중복 연결 감지 -> 기존 연결 종료", "agent_id", s.AgentID)
			old.(*tls.Conn).Close()
		}
		s.sessions.Store(s.AgentID, s.conn)
	}

	// DB 저장
	p := internal.RegisterPayload{
		Hostname:    reg.Hostname,
		IP:          reg.IP.String(),
		OS:          reg.OS,
		MonitorType: MonitorTypeName(reg.MonitorType),
	}
	if err := s.agents.RegisterAgent(s.ctx, s.AgentID, p); err != nil {
		slog.Error("RegisterAgent 실패", "err", err)
		return
	}

	// ACK 전송
	resp := EncodeRegisterResp(s.agentNum)
	if err := WriteFrame(s.conn, MsgRegister, hdr.SeqNum, resp); err != nil {
		slog.Error("REGISTER ACK 전송 실패", "err", err)
	}

	slog.Info("에이전트 등록", "agent_id", s.AgentID, "hostname", reg.Hostname, "ip", reg.IP.String())
}

// handleHeartbeat : 0x02 HEARTBEAT -> last_seen 갱신
func (s *AgentSession) handleHeartbeat(payload []byte) {
	hb, err := DecodeHeartbeat(payload)
	if err != nil {
		slog.Warn("HEARTBEAT 디코딩 실패", "err", err)
		return
	}

	agentID := strconv.FormatUint(hb.AgentID, 10)
	if err := s.agents.UpdateHeartbeat(s.ctx, agentID, time.Unix(int64(hb.Timestamp), 0)); err != nil {
		slog.Warn("UpdateHeartbeat 실패", "err", err)
	}
}

// handleFileEvent : 0x03 FILE_EVENT -> DB 저장 + SSE push + engine 전달
func (s *AgentSession) handleFileEvent(payload []byte) {
	ev, err := DecodeFileEvent(payload)
	if err != nil {
		slog.Warn("FILE_EVENT 디코딩 실패", "err", err)
		return
	}

	agentID := strconv.FormatUint(ev.AgentID, 10)

	// 바이너리 -> internal 타입 변환
	p := internal.FileEventPayload{
		AgentID:        agentID,
		EventType:      EventTypeName(ev.EventType),
		FilePath:       ev.FilePath,
		FileName:       ev.FileName,
		FileHash:       hex.EncodeToString(ev.FileHash[:]),
		FilePermission: PermString(ev.FilePermission),
		DetectedBy:     MonitorTypeName(ev.DetectedBy),
		Pid:            int(ev.Pid),
		Timestamp:      int64(ev.Timestamp),
	}

	// DB 저장
	if err := s.events.SaveEvent(s.ctx, p); err != nil {
		slog.Error("SaveEvent 실패", "err", err)
	}

	// SSE 실시간 push
	e := internal.FileEvent{
		AgentID:        agentID,
		EventType:      p.EventType,
		FilePath:       p.FilePath,
		FileName:       p.FileName,
		FileHash:       p.FileHash,
		FilePermission: p.FilePermission,
		DetectedBy:     p.DetectedBy,
		Pid:            p.Pid,
		OccurredAt:     time.Unix(p.Timestamp, 0),
	}
	s.pub.Publish(e)

	// engine -> 이상 감지 전달
	if s.onEvent != nil {
		s.onEvent(s.ctx, agentID, e)
	}
}
