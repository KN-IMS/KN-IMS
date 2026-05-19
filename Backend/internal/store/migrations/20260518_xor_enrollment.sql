-- XOR bootstrap enrollment schema for existing KN-IG databases.
-- Run once before using cmd/enroll-token with the interactive XOR enrollment flow.

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
