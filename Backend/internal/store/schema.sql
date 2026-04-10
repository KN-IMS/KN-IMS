CREATE DATABASE IF NOT EXISTS fims
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_bin;

USE fims;

CREATE TABLE IF NOT EXISTS user (
    user_id    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username   VARCHAR(50)     NOT NULL UNIQUE,
    password   VARCHAR(255)    NOT NULL,
    created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id),
    UNIQUE INDEX idx_user_username (username)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS agent (
    agent_id      CHAR(36)     NOT NULL,
    hostname      VARCHAR(255) NOT NULL,
    ip            VARCHAR(45)  NOT NULL,
    os            VARCHAR(100) NOT NULL,
    version       VARCHAR(50)  NOT NULL,
    status        TINYINT(1)   NOT NULL DEFAULT 1,
    registered_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (agent_id),
    INDEX idx_agent_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS file (
    agent_id        CHAR(36)      NOT NULL,
    file_path_hash  CHAR(64)      NOT NULL,
    file_path       VARCHAR(4096) NOT NULL,
    file_hash       CHAR(64)      NOT NULL,
    file_permission VARCHAR(4)    NOT NULL,
    mod_time        DATETIME      NOT NULL,
    updated_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
                                  ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (agent_id, file_path_hash),
    CONSTRAINT fk_file_agent
        FOREIGN KEY (agent_id) REFERENCES agent(agent_id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alert (
    alert_id    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    agent_id    CHAR(36)        NOT NULL,
    file_path   VARCHAR(4096)   NOT NULL,
    event_type  ENUM('CREATE', 'MODIFY', 'DELETE') NOT NULL,
    detected_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (alert_id),
    INDEX idx_alert_agent (agent_id),
    INDEX idx_alert_time  (detected_at),
    CONSTRAINT fk_alert_agent
        FOREIGN KEY (agent_id) REFERENCES agent(agent_id)
        ON DELETE CASCADE
) ENGINE=InnoDB;
