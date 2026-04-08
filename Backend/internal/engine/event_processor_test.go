package engine

import (
	"context"
	"testing"
	"time"

	"github.com/KGU-FIMS/Backend/internal"
)

// mockAlertStore : AlertStore 테스트용 mock
type mockAlertStore struct {
	created []mockAlert
	err     error
}

type mockAlert struct {
	agentID  string
	severity string
	message  string
}

func (m *mockAlertStore) CreateAlert(_ context.Context, agentID, severity, message string) error {
	if m.err != nil {
		return m.err
	}
	m.created = append(m.created, mockAlert{agentID, severity, message})
	return nil
}

func (m *mockAlertStore) ListAlerts(_ context.Context, _ internal.AlertFilter) ([]internal.Alert, error) {
	return nil, nil
}

func (m *mockAlertStore) ResolveAlert(_ context.Context, _ int64) error {
	return nil
}

func TestIsSensitivePath(t *testing.T) {
	p := NewEventProcessor(&mockAlertStore{})

	cases := []struct {
		path string
		want bool
	}{
		{"/etc/passwd", true},
		{"/bin/bash", true},
		{"/sbin/init", true},
		{"/usr/bin/python3", true},
		{"/usr/sbin/sshd", true},
		{"/boot/grub/grub.cfg", true},
		{"/lib/systemd/systemd", true},
		{"/home/user/file.txt", false},
		{"/var/log/syslog", false},
		{"/tmp/test", false},
		{"/opt/app/config", false},
	}

	for _, c := range cases {
		got := p.isSensitivePath(c.path)
		if got != c.want {
			t.Errorf("isSensitivePath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestDetectBurst_UnderThreshold(t *testing.T) {
	p := NewEventProcessor(&mockAlertStore{})

	// 99건 -> burst 아님
	for i := 0; i < 99; i++ {
		if p.detectBurst("agent-1") {
			t.Fatalf("99번째에서 burst 감지됨 (기대: false)")
		}
	}
}

func TestDetectBurst_AtThreshold(t *testing.T) {
	p := NewEventProcessor(&mockAlertStore{})

	// 99건 선 삽입
	for i := 0; i < 99; i++ {
		p.detectBurst("agent-1")
	}
	// 100번째 -> burst
	if !p.detectBurst("agent-1") {
		t.Fatal("100번째에서 burst 미감지 (기대: true)")
	}
}

func TestDetectBurst_MultipleAgents(t *testing.T) {
	p := NewEventProcessor(&mockAlertStore{})

	// agent-1 에 99건
	for i := 0; i < 99; i++ {
		p.detectBurst("agent-1")
	}
	// agent-2 는 독립적 -> burst 아님
	if p.detectBurst("agent-2") {
		t.Fatal("다른 에이전트에 burst 감지됨 (기대: false)")
	}
}

func TestProcess_SensitivePath_CreatesHighAlert(t *testing.T) {
	store := &mockAlertStore{}
	p := NewEventProcessor(store)
	ctx := context.Background()

	e := internal.FileEvent{
		EventType:  "MODIFY",
		FilePath:   "/etc/passwd",
		DetectedBy: "inotify",
		OccurredAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
	}

	p.Process(ctx, "agent-1", e)

	if len(store.created) != 1 {
		t.Fatalf("알림 수 = %d, want 1", len(store.created))
	}
	if store.created[0].severity != internal.SeverityHigh {
		t.Errorf("severity = %q, want HIGH", store.created[0].severity)
	}
}

func TestProcess_NightTime_CreatesMediumAlert(t *testing.T) {
	store := &mockAlertStore{}
	p := NewEventProcessor(store)
	ctx := context.Background()

	e := internal.FileEvent{
		EventType:  "CREATE",
		FilePath:   "/home/user/test.txt",
		DetectedBy: "inotify",
		OccurredAt: time.Date(2026, 1, 1, 23, 0, 0, 0, time.UTC),
	}

	p.Process(ctx, "agent-1", e)

	if len(store.created) != 1 {
		t.Fatalf("알림 수 = %d, want 1", len(store.created))
	}
	if store.created[0].severity != internal.SeverityMedium {
		t.Errorf("severity = %q, want MEDIUM", store.created[0].severity)
	}
}

func TestProcess_NormalEvent_NoAlert(t *testing.T) {
	store := &mockAlertStore{}
	p := NewEventProcessor(store)
	ctx := context.Background()

	e := internal.FileEvent{
		EventType:  "MODIFY",
		FilePath:   "/home/user/doc.txt",
		DetectedBy: "inotify",
		OccurredAt: time.Date(2026, 1, 1, 14, 0, 0, 0, time.UTC),
	}

	p.Process(ctx, "agent-1", e)

	if len(store.created) != 0 {
		t.Errorf("알림 수 = %d, want 0", len(store.created))
	}
}

func TestProcess_SensitiveAndNight_TwoAlerts(t *testing.T) {
	store := &mockAlertStore{}
	p := NewEventProcessor(store)
	ctx := context.Background()

	e := internal.FileEvent{
		EventType:  "MODIFY",
		FilePath:   "/etc/shadow",
		DetectedBy: "inotify",
		OccurredAt: time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC),
	}

	p.Process(ctx, "agent-1", e)

	// HIGH (민감경로) + MEDIUM (야간) = 2건
	if len(store.created) != 2 {
		t.Fatalf("알림 수 = %d, want 2", len(store.created))
	}
}
