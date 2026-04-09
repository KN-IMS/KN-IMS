-- fim-server DB 스키마
-- MySQL 8.0+

-- ── 에이전트 ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agents (
    agent_id      VARCHAR(36)  PRIMARY KEY,
    hostname      VARCHAR(255) NOT NULL,
    ip            VARCHAR(45)  NOT NULL,
    version       VARCHAR(20)  NOT NULL,
    os            VARCHAR(100) NOT NULL,
    monitor_type  VARCHAR(20)  NOT NULL DEFAULT 'lkm',
    status        VARCHAR(10)  NOT NULL DEFAULT 'online',
    registered_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen     DATETIME     DEFAULT NULL
);

-- ── 파일 이벤트 ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS file_events (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    agent_id        VARCHAR(36)  NOT NULL,
    event_type      VARCHAR(10)  NOT NULL,
    file_path       TEXT         NOT NULL,
    file_name       VARCHAR(255) NOT NULL,
    file_permission VARCHAR(10)  NOT NULL DEFAULT '',
    detected_by     VARCHAR(20)  NOT NULL DEFAULT 'lkm',
    pid             INT          NOT NULL DEFAULT 0,
    occurred_at     DATETIME     NOT NULL,
    received_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX idx_file_events_agent_id ON file_events(agent_id);
CREATE INDEX idx_file_events_occurred_at ON file_events(occurred_at DESC);
CREATE INDEX idx_file_events_event_type ON file_events(event_type);

-- ── 알림 ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id          BIGINT       AUTO_INCREMENT PRIMARY KEY,
    agent_id    VARCHAR(36)  NOT NULL,
    severity    VARCHAR(10)  NOT NULL,
    message     TEXT         NOT NULL,
    resolved    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX idx_alerts_agent_id ON alerts(agent_id);
CREATE INDEX idx_alerts_resolved ON alerts(resolved);
CREATE INDEX idx_alerts_severity ON alerts(severity);
