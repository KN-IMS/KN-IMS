package engine

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// EventProcessor : FILE_EVENT 수신 후 이상 감지 -> AlertStore 호출
type EventProcessor struct {
	alerts internal.AlertStore
	// burst 감지 -> agentID별 1분 내 이벤트 타임스탬프
	burstMu    sync.Mutex
	burstCount map[string][]time.Time
}

// NewEventProcessor : EventProcessor 생성
func NewEventProcessor(alerts internal.AlertStore) *EventProcessor {
	return &EventProcessor{
		alerts:     alerts,
		burstCount: make(map[string][]time.Time),
	}
}

// Process : collector의 onEvent 콜백으로 호출
func (p *EventProcessor) Process(ctx context.Context, agentID string, e internal.FileEvent) {
	// 민감 경로 변경 감지 -> HIGH
	if p.isSensitivePath(e.FilePath) {
		msg := fmt.Sprintf("[민감경로 %s 변경 감지: %s (%s)]", e.EventType, e.FilePath, e.DetectedBy)
		p.createAlert(ctx, agentID, internal.SeverityHigh, msg)
	}

	// 취약 시간대 변경 감지 -> default (22:00 ~ 06:00)
	hour := e.OccurredAt.Hour()
	if hour >= 22 || hour < 6 {
		msg := fmt.Sprintf("[%s: %s (%02d시) 변경 감지]", e.EventType, e.FilePath, hour)
		p.createAlert(ctx, agentID, internal.SeverityMedium, msg)
	}

	// Burst 감지 -> HIGH (1분 내 100건 이상)
	if p.detectBurst(agentID) {
		msg := fmt.Sprintf("[대량변경감지]")
		p.createAlert(ctx, agentID, internal.SeverityHigh, msg)
	}
}

// isSensitivePath : 민감 경로 여부 확인 -> 현재는 임의 설정
func (p *EventProcessor) isSensitivePath(path string) bool {
	sensitive := []string{
		"/etc/", "/bin/", "/sbin/",
		"/usr/bin/", "/usr/sbin/",
		"/boot/", "/lib/",
	}
	for _, prefix := range sensitive {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// detectBurst : 1분 내 이벤트 100건 이상 -> true
func (p *EventProcessor) detectBurst(agentID string) bool {
	p.burstMu.Lock()
	defer p.burstMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	// 1분 이전 항목 제거
	times := p.burstCount[agentID]
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	p.burstCount[agentID] = valid

	return len(valid) >= 100
}

// createAlert : AlertStore 호출 + 로그
func (p *EventProcessor) createAlert(ctx context.Context, agentID, severity, msg string) {
	if err := p.alerts.CreateAlert(ctx, agentID, severity, msg); err != nil {
		slog.Error("알림 생성 실패", "err", err)
		return
	}
	slog.Warn("이상 감지", "agent_id", agentID, "severity", severity, "msg", msg)
}
