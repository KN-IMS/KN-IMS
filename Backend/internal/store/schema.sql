-- ig-server DB 스키마
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

-- ── Agent mTLS 인증서 binding ───────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_certificates (
    id                BIGINT       AUTO_INCREMENT PRIMARY KEY,
    agent_id          VARCHAR(36)  NOT NULL,
    cert_subject_hash CHAR(64)     NOT NULL,
    cert_fingerprint  CHAR(64)     NOT NULL,
    status            VARCHAR(16)  NOT NULL DEFAULT 'active',
    issued_at         DATETIME     DEFAULT NULL,
    expires_at        DATETIME     DEFAULT NULL,
    bound_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at        DATETIME     DEFAULT NULL,
    UNIQUE KEY uq_agent_cert_subject_hash (cert_subject_hash),
    UNIQUE KEY uq_agent_cert_fingerprint (cert_fingerprint),
    KEY idx_agent_certificates_agent_status (agent_id, status),
    CONSTRAINT fk_agent_certificates_agent
        FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        ON DELETE CASCADE
);

-- ── Agent 최초 등록 XOR bootstrap key ───────────────────────────
CREATE TABLE IF NOT EXISTS agent_enrollments (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    enrollment_id   VARCHAR(64)  NOT NULL,
    agent_id        VARCHAR(36)  DEFAULT NULL,
    secret_hash     CHAR(64)     NOT NULL,
    key_ciphertext  VARBINARY(512) DEFAULT NULL,
    key_nonce       VARBINARY(32)  DEFAULT NULL,
    status          VARCHAR(16)  NOT NULL DEFAULT 'pending',
    expires_at      DATETIME     NOT NULL,
    issued_at       DATETIME     DEFAULT NULL,
    used_at         DATETIME     DEFAULT NULL,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempt_count   INT          NOT NULL DEFAULT 0,
    last_attempt_at DATETIME     DEFAULT NULL,
    UNIQUE KEY uq_agent_enrollments_enrollment_id (enrollment_id),
    KEY idx_agent_enrollments_agent (agent_id),
    KEY idx_agent_enrollments_status_expires (status, expires_at)
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
    target_dev      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    target_ino      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    blocked         TINYINT(1)   NOT NULL DEFAULT 0,
    actor_pid       INT          NOT NULL DEFAULT 0,
    actor_ppid      INT          NOT NULL DEFAULT 0,
    actor_uid       INT UNSIGNED NOT NULL DEFAULT 0,
    actor_euid      INT UNSIGNED NOT NULL DEFAULT 0,
    actor_sid       INT          NOT NULL DEFAULT 0,
    actor_tty       VARCHAR(32)  NOT NULL DEFAULT '',
    actor_comm      VARCHAR(16)  NOT NULL DEFAULT '',
    actor_exe       VARCHAR(256) NOT NULL DEFAULT '',
    actor_cmdline   TEXT,
    actor_start_time_ns BIGINT UNSIGNED NOT NULL DEFAULT 0,
    chain_depth     TINYINT UNSIGNED NOT NULL DEFAULT 0,
    chain_truncated TINYINT(1)   NOT NULL DEFAULT 0,
    occurred_at     DATETIME     NOT NULL,
    received_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX idx_file_events_agent_id ON file_events(agent_id);
CREATE INDEX idx_file_events_occurred_at ON file_events(occurred_at DESC);
CREATE INDEX idx_file_events_event_type ON file_events(event_type);
CREATE INDEX idx_file_events_target_inode ON file_events(target_dev, target_ino);
CREATE INDEX idx_file_events_actor_pid ON file_events(actor_pid);

CREATE TABLE IF NOT EXISTS file_event_process_chain (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    event_id        BIGINT       NOT NULL,
    depth_index     TINYINT UNSIGNED NOT NULL,
    pid             INT          NOT NULL DEFAULT 0,
    ppid            INT          NOT NULL DEFAULT 0,
    uid             INT UNSIGNED NOT NULL DEFAULT 0,
    euid            INT UNSIGNED NOT NULL DEFAULT 0,
    sid             INT          NOT NULL DEFAULT 0,
    tty             VARCHAR(32)  NOT NULL DEFAULT '',
    comm            VARCHAR(16)  NOT NULL DEFAULT '',
    exe             VARCHAR(256) NOT NULL DEFAULT '',
    cmdline         TEXT,
    start_time_ns   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    FOREIGN KEY (event_id) REFERENCES file_events(id) ON DELETE CASCADE,
    UNIQUE KEY uniq_event_chain_depth (event_id, depth_index),
    INDEX idx_event_chain_pid (pid),
    INDEX idx_event_chain_uid (uid),
    INDEX idx_event_chain_euid (euid)
);

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

-- ── 인증 (콘솔 PIN) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_state (
    id         TINYINT      PRIMARY KEY,
    pin_hash   VARCHAR(60)  NOT NULL,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CHECK (id = 1)
);
