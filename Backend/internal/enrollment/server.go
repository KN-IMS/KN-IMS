package enrollment

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/KN-IG/KN-IG/Backend/internal"
)

// Server : 인증서가 없는 신규 Agent용 XOR protected enrollment TCP listener
type Server struct {
	addr        string
	svc         *Service
	enrollments internal.EnrollmentStore
	keyVault    *KeyVault
	pepper      string
}

func NewServer(addr string, svc *Service, enrollments internal.EnrollmentStore, keyVault *KeyVault, pepper string) *Server {
	return &Server{addr: addr, svc: svc, enrollments: enrollments, keyVault: keyVault, pepper: pepper}
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("enrollment 리스너 시작 실패 (%s): %w", s.addr, err)
	}
	defer ln.Close()
	slog.Info("Enrollment 서버 시작", "addr", s.addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("enrollment 연결 수락 실패", "err", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(raw net.Conn) {
	conn := raw
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	hdr, payload, err := readFrame(conn)
	if err != nil {
		slog.Warn("enrollment frame 수신 실패", "err", err)
		return
	}
	if hdr.msgTyp != MsgXORHello {
		s.writeError(conn, hdr.seqNum, "unexpected enrollment message type")
		return
	}

	hello, err := decodeHello(payload)
	if err != nil {
		slog.Warn("enrollment hello decode 실패", "err", err)
		s.writeError(conn, hdr.seqNum, "invalid enrollment hello")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	row, err := s.enrollments.GetPendingEnrollment(ctx, hello.EnrollmentID, time.Now().UTC())
	if err != nil {
		slog.Warn("Agent enrollment 시작 실패", "enrollment_id", hello.EnrollmentID, "err", err)
		s.writeError(conn, hdr.seqNum, err.Error())
		return
	}
	xorKey, err := s.keyVault.Decrypt(row.KeyCiphertext, row.KeyNonce)
	if err != nil {
		slog.Warn("Agent enrollment key 복호화 실패", "enrollment_id", hello.EnrollmentID, "err", err)
		s.writeError(conn, hdr.seqNum, "enrollment key unavailable")
		return
	}
	defer ZeroBytes(xorKey)
	if row.SecretHash != HashXORKey(hello.EnrollmentID, xorKey, s.pepper) {
		slog.Warn("Agent enrollment key hash 검증 실패", "enrollment_id", hello.EnrollmentID)
		s.writeError(conn, hdr.seqNum, "enrollment key validation failed")
		return
	}

	serverNonce := make([]byte, nonceSize)
	if _, err := rand.Read(serverNonce); err != nil {
		s.writeError(conn, hdr.seqNum, "nonce generation failed")
		return
	}
	defer ZeroBytes(serverNonce)

	keys, err := DeriveSessionKeys(xorKey, hello.EnrollmentID, hello.ClientNonce, serverNonce)
	if err != nil {
		s.writeError(conn, hdr.seqNum, "session key derivation failed")
		return
	}
	defer keys.Clear()

	chPayload, err := encodeChallenge(Challenge{
		ServerNonce: serverNonce,
		Proof:       ServerProof(&keys, hello.EnrollmentID, hello.ClientNonce, serverNonce),
	})
	if err != nil {
		s.writeError(conn, hdr.seqNum, "challenge encode failed")
		return
	}
	if err := writeFrame(conn, MsgXORChallenge, hdr.seqNum+1, chPayload); err != nil {
		slog.Warn("enrollment challenge 전송 실패", "enrollment_id", hello.EnrollmentID, "err", err)
		return
	}
	ZeroBytes(chPayload)

	reqHdr, protectedReq, err := readFrame(conn)
	if err != nil {
		slog.Warn("enrollment request 수신 실패", "enrollment_id", hello.EnrollmentID, "err", err)
		return
	}
	if reqHdr.msgTyp != MsgXOREnrollRequest {
		s.writeError(conn, reqHdr.seqNum, "unexpected protected request type")
		return
	}
	reqPlain, err := OpenProtected(reqHdr.msgTyp, reqHdr.seqNum, protectedReq, &keys)
	if err != nil {
		slog.Warn("enrollment protected request 검증 실패", "enrollment_id", hello.EnrollmentID, "err", err)
		s.writeError(conn, reqHdr.seqNum, "invalid protected request")
		return
	}
	defer ZeroBytes(reqPlain)

	req, err := decodeRequest(reqPlain)
	if err != nil {
		slog.Warn("enrollment request decode 실패", "enrollment_id", hello.EnrollmentID, "err", err)
		s.writeError(conn, reqHdr.seqNum, "invalid enrollment request")
		return
	}

	resp, err := s.svc.Enroll(ctx, hello.EnrollmentID, req)
	if err != nil {
		slog.Warn("Agent enrollment 실패", "enrollment_id", hello.EnrollmentID, "hostname", req.Hostname, "err", err)
		s.writeError(conn, reqHdr.seqNum, err.Error())
		return
	}
	defer ZeroBytes(resp.AgentKeyPEM)

	respPlain, err := encodeResponse(resp)
	if err != nil {
		slog.Warn("enrollment response encode 실패", "agent_id", resp.AgentID, "err", err)
		s.writeError(conn, reqHdr.seqNum, "response encode failed")
		return
	}
	defer ZeroBytes(respPlain)
	protectedResp, err := SealProtected(MsgXOREnrollResponse, reqHdr.seqNum+1, respPlain, &keys)
	if err != nil {
		s.writeError(conn, reqHdr.seqNum, "response protect failed")
		return
	}
	if err := writeFrame(conn, MsgXOREnrollResponse, reqHdr.seqNum+1, protectedResp); err != nil {
		slog.Warn("enrollment response 전송 실패", "agent_id", resp.AgentID, "err", err)
		return
	}
	ZeroBytes(protectedResp)

	ackHdr, protectedAck, err := readFrame(conn)
	if err == nil && ackHdr.msgTyp == MsgXOREnrollAck {
		if ackPlain, err := OpenProtected(ackHdr.msgTyp, ackHdr.seqNum, protectedAck, &keys); err == nil {
			ZeroBytes(ackPlain)
			if err := s.enrollments.MarkEnrollmentUsed(ctx, hello.EnrollmentID, resp.AgentID, time.Now().UTC()); err != nil {
				slog.Warn("Agent enrollment ACK 처리 실패", "agent_id", resp.AgentID, "err", err)
			}
		}
	}

	slog.Info("Agent enrollment 성공", "agent_id", resp.AgentID, "expires_at", resp.ExpiresAt)
}

func (s *Server) writeError(conn net.Conn, seqNum uint32, message string) {
	payload, err := encodeError(message)
	if err != nil {
		return
	}
	_ = writeFrame(conn, MsgXOREnrollError, seqNum, payload)
}
