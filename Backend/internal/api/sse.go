package api

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/gin-gonic/gin"
	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// SSEPublisher : EventPublisher 인터페이스의 구현체
// Server-Sent Events(SSE)를 통해 실시간 알림을 브라우저에 푸시
type SSEPublisher struct {
	clients map[chan internal.Alert]bool
}

// NewSSEPublisher : SSEPublisher 생성자
// main.go에서 생성하여 Server에 주입
func NewSSEPublisher() *SSEPublisher {
	return &SSEPublisher{
		clients: make(map[chan internal.Alert]bool),
	}
}

// Publish : 새 알림을 모든 구독 클라이언트에게 전달
// collector가 파일 변경 이벤트를 수신했을 때 호출
func (p *SSEPublisher) Publish(event internal.Alert) {
	for ch := range p.clients {
		select {
		case ch <- event:
		default:
		}
	}
}

// Subscribe : 새 클라이언트의 구독 채널 생성
// handleSSE에서 호출하여 SSE 연결마다 전용 채널 할당
func (p *SSEPublisher) Subscribe() <-chan internal.Alert {
	ch := make(chan internal.Alert, 100)
	p.clients[ch] = true
	return ch
}

// Unsubscribe : 클라이언트 구독 해제 및 채널 정리
// SSE 연결이 끊어졌을 때 (브라우저 탭 닫기 등) 호출
// 채널을 close하여 메모리 누수 방지
func (p *SSEPublisher) Unsubscribe(ch <-chan internal.Alert) {
	for c := range p.clients {
		if c == ch {
			delete(p.clients, c)
			close(c)
			return
		}
	}
}

// handleSSE : GET /api/events/stream
// SSE(Server-Sent Events) 엔드포인트
func (s *Server) handleSSE(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	pub, ok := s.publisher.(*SSEPublisher)
	if !ok {
		return
	}

	ch := pub.Subscribe()
	defer pub.Unsubscribe(ch)

	c.Stream(func(w io.Writer) bool {
		select {
		case event, ok := <-ch:
			if !ok {
				return false
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data:%s\n\n", data)
			return true
		case <-c.Request.Context().Done():
			return false
		}
	})
}