package collector

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// Server : TCP 리스너 + 세션 관리
type Server struct {
	addr     string
	tlsCfg   *tls.Config
	agents   internal.AgentStore
	events   internal.EventStore
	scans    internal.ScanStore
	alerts   internal.AlertStore
	pub      internal.EventPublisher
	onEvent  func(ctx context.Context, agentID string, e internal.FileEvent)
	sessions sync.Map // agentID(string) -> *tls.Conn
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
