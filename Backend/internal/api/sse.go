package api

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
	"github.com/gin-gonic/gin"
)

// SSEPublisher : EventPublisher 인터페이스의 구현체
type SSEPublisher struct {
	mu      sync.RWMutex
	clients map[chan internal.FileEvent]struct{}
}

// NewSSEPublisher : SSEPublisher 생성
func NewSSEPublisher() *SSEPublisher {
	return &SSEPublisher{
		clients: make(map[chan internal.FileEvent]struct{}),
	}
}

// Publish : 모든 구독자에게 이벤트 전송
func (p *SSEPublisher) Publish(event internal.FileEvent) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for ch := range p.clients {
		select {
		case ch <- event:
		default:
			// 클라이언트가 느리면 건너뜀
		}
	}
}

// Subscribe : 새 구독 채널 생성
func (p *SSEPublisher) Subscribe() <-chan internal.FileEvent {
	ch := make(chan internal.FileEvent, 100)
	p.mu.Lock()
	p.clients[ch] = struct{}{}
	p.mu.Unlock()
	return ch
}

// Unsubscribe : 구독 해제
func (p *SSEPublisher) Unsubscribe(ch <-chan internal.FileEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for c := range p.clients {
		if c == ch {
			delete(p.clients, c)
			close(c)
			return
		}
	}
}

// handleSSE : GET /api/events/stream
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
