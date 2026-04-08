package collector

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KGU-FIMS/Backend/internal"
)

// Server : TCP 리스너 + 세션 관리 + CommandSender 구현체
type Server struct {
	addr     string
	tlsCfg   *tls.Config
	agents   internal.AgentStore
	events   internal.EventStore
	scans    internal.ScanStore
	alerts   internal.AlertStore
	pub      internal.EventPublisher
	onEvent  func(ctx context.Context, agentID string, e internal.FileEvent)
	sessions sync.Map      // agentID(string) -> *tls.Conn
	seqNum   atomic.Uint32 // 서버 -> 에이전트 seq_num
}

// NewServer : TCP 서버 생성
func NewServer(
	addr string,
	tlsCfg *tls.Config,
	agents internal.AgentStore,
	events internal.EventStore,
	scans internal.ScanStore,
	alerts internal.AlertStore,
	pub internal.EventPublisher,
	onEvent func(context.Context, string, internal.FileEvent),
) *Server {
	return &Server{
		addr:    addr,
		tlsCfg:  tlsCfg,
		agents:  agents,
		events:  events,
		scans:   scans,
		alerts:  alerts,
		pub:     pub,
		onEvent: onEvent,
	}
}

// Start : TCP mTLS 리스너 시작 -> blocking
func (s *Server) Start() error {
	ln, err := tls.Listen("tcp", s.addr, s.tlsCfg)
	if err != nil {
		return fmt.Errorf("TCP 리스너 시작 실패 (%s): %w", s.addr, err)
	}
	defer ln.Close()
	slog.Info("TCP 서버 시작", "addr", s.addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("연결 수락 실패", "err", err)
			continue
		}
		go s.handleConn(conn.(*tls.Conn))
	}
}

// handleConn : 연결당 goroutine -> TLS 핸드셰이크 + 세션 실행
func (s *Server) handleConn(conn *tls.Conn) {
	// TLS 핸드셰이크 -> 10초 타임아웃
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		slog.Warn("TLS 핸드셰이크 실패", "err", err)
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{}) // 타임아웃 해제

	session := &AgentSession{
		conn:     conn,
		agents:   s.agents,
		events:   s.events,
		scans:    s.scans,
		alerts:   s.alerts,
		pub:      s.pub,
		onEvent:  s.onEvent,
		sessions: &s.sessions,
	}

	session.Run()
}

// nextSeq : 서버 -> 에이전트 전송 시 seq_num 증가
func (s *Server) nextSeq() uint32 {
	return s.seqNum.Add(1)
}

// SendCreateBaseline : POST /api/agents/:id/baseline -> 0x05 CREATE_BASELINE
func (s *Server) SendCreateBaseline(ctx context.Context, agentID, path string) error {
	cmd := &CommandMsg{
		Type: CmdCreateBaseline,
		Path: path,
	}
	return s.sendCommand(ctx, agentID, cmd)
}

// SendIntegrityScan : POST /api/agents/:id/scan -> 0x05 INTEGRITY_SCAN
func (s *Server) SendIntegrityScan(ctx context.Context, agentID, path string) error {
	cmd := &CommandMsg{
		Type: CmdIntegrityScan,
		Path: path,
	}
	return s.sendCommand(ctx, agentID, cmd)
}

// SendAddWatch : watch 경로 추가 -> 0x05 ADD_WATCH
func (s *Server) SendAddWatch(ctx context.Context, agentID, path string, recursive bool) error {
	cmd := &CommandMsg{
		Type:      CmdAddWatch,
		Path:      path,
		Recursive: recursive,
	}
	return s.sendCommand(ctx, agentID, cmd)
}

// SendRemoveWatch : watch 경로 제거 -> 0x05 REMOVE_WATCH
func (s *Server) SendRemoveWatch(ctx context.Context, agentID, path string) error {
	cmd := &CommandMsg{
		Type: CmdRemoveWatch,
		Path: path,
	}
	return s.sendCommand(ctx, agentID, cmd)
}

// SendConfigUpdate : 설정 업데이트 -> 0x05 CONFIG_UPDATE
func (s *Server) SendConfigUpdate(ctx context.Context, agentID string, args string) error {
	cmd := &CommandMsg{
		Type: CmdConfigUpdate,
	}
	cmd.Args = parseConfigArgs(args)
	return s.sendCommand(ctx, agentID, cmd)
}

// sendCommand : 공통 COMMAND 전송 -> 바이너리 직렬화
func (s *Server) sendCommand(ctx context.Context, agentID string, cmd *CommandMsg) error {
	val, ok := s.sessions.Load(agentID)
	if !ok {
		return fmt.Errorf("%w: %s", internal.ErrAgentOffline, agentID)
	}
	conn := val.(*tls.Conn)

	payload := EncodeCommand(cmd)
	return WriteFrame(conn, MsgCommand, s.nextSeq(), payload)
}

// parseConfigArgs : 문자열 -> CommandArgs 변환
func parseConfigArgs(args string) CommandArgs {
	var ca CommandArgs
	_ = args
	return ca
}
