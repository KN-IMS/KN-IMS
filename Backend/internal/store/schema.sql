-- fim-server DB 스키마
-- MySQL 8.0+

DROP PROCEDURE IF EXISTS create_index_if_missing;

DELIMITER $$
CREATE PROCEDURE create_index_if_missing(
    IN p_table_name VARCHAR(64),
    IN p_index_name VARCHAR(64),
    IN p_statement VARCHAR(1024)
)
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = p_table_name
          AND INDEX_NAME = p_index_name
    ) THEN
        SET @create_index_sql = p_statement;
        PREPARE create_index_stmt FROM @create_index_sql;
        EXECUTE create_index_stmt;
        DEALLOCATE PREPARE create_index_stmt;
    END IF;
END$$
DELIMITER ;

-- ── 에이전트 ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agents (
    agent_id      VARCHAR(36)  PRIMARY KEY,
    hostname      VARCHAR(255) NOT NULL,
    ip            VARCHAR(45)  NOT NULL,
    version       VARCHAR(20)  NOT NULL,
    os            VARCHAR(100) NOT NULL,
    monitor_type  VARCHAR(20)  NOT NULL DEFAULT 'inotify',
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
    file_hash       VARCHAR(64)  NOT NULL DEFAULT '',
    file_permission VARCHAR(10)  NOT NULL DEFAULT '',
    detected_by     VARCHAR(20)  NOT NULL DEFAULT 'inotify',
    pid             INT          NOT NULL DEFAULT 0,
    occurred_at     DATETIME     NOT NULL,
    received_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

CALL create_index_if_missing('file_events', 'idx_file_events_agent_id', 'CREATE INDEX idx_file_events_agent_id ON file_events(agent_id)');
CALL create_index_if_missing('file_events', 'idx_file_events_occurred_at', 'CREATE INDEX idx_file_events_occurred_at ON file_events(occurred_at DESC)');
CALL create_index_if_missing('file_events', 'idx_file_events_event_type', 'CREATE INDEX idx_file_events_event_type ON file_events(event_type)');

-- ── 스캔 결과 요약 ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_results (
    id          BIGINT       AUTO_INCREMENT PRIMARY KEY,
    agent_id    VARCHAR(36)  NOT NULL,
    scan_type   VARCHAR(20)  NOT NULL,
    scan_path   TEXT         NOT NULL,
    total       INT          NOT NULL DEFAULT 0,
    changed     INT          NOT NULL DEFAULT 0,
    scanned_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

CALL create_index_if_missing('scan_results', 'idx_scan_results_agent_id', 'CREATE INDEX idx_scan_results_agent_id ON scan_results(agent_id)');

-- ── 스캔 결과 개별 파일 항목 ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_entries (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    scan_id         BIGINT       NOT NULL,
    file_path       TEXT         NOT NULL,
    file_name       VARCHAR(255) NOT NULL,
    file_hash       VARCHAR(64)  NOT NULL DEFAULT '',
    file_permission VARCHAR(10)  NOT NULL DEFAULT '',
    size            BIGINT       NOT NULL DEFAULT 0,
    mod_time        DATETIME     DEFAULT NULL,
    changed         BOOLEAN      NOT NULL DEFAULT FALSE,
    FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE
);

CALL create_index_if_missing('scan_entries', 'idx_scan_entries_scan_id', 'CREATE INDEX idx_scan_entries_scan_id ON scan_entries(scan_id)');
CALL create_index_if_missing('scan_entries', 'idx_scan_entries_changed', 'CREATE INDEX idx_scan_entries_changed ON scan_entries(changed)');

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

CALL create_index_if_missing('alerts', 'idx_alerts_agent_id', 'CREATE INDEX idx_alerts_agent_id ON alerts(agent_id)');
CALL create_index_if_missing('alerts', 'idx_alerts_resolved', 'CREATE INDEX idx_alerts_resolved ON alerts(resolved)');
CALL create_index_if_missing('alerts', 'idx_alerts_severity', 'CREATE INDEX idx_alerts_severity ON alerts(severity)');

DROP PROCEDURE IF EXISTS create_index_if_missing;
