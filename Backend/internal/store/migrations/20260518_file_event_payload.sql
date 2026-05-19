-- FILE_EVENT payload schema sync for Agent inode/blocked/process-chain fields.
-- This migration is written without ADD COLUMN IF NOT EXISTS for older MySQL compatibility.

DROP PROCEDURE IF EXISTS knig_add_file_event_column;
DROP PROCEDURE IF EXISTS knig_add_file_event_index;

DELIMITER $$

CREATE PROCEDURE knig_add_file_event_column(IN p_column_name VARCHAR(64), IN p_column_def VARCHAR(1024))
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'file_events'
          AND COLUMN_NAME = p_column_name
    ) THEN
        SET @ddl = CONCAT('ALTER TABLE file_events ADD COLUMN ', p_column_def);
        PREPARE stmt FROM @ddl;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END$$

CREATE PROCEDURE knig_add_file_event_index(IN p_index_name VARCHAR(64), IN p_index_def VARCHAR(1024))
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'file_events'
          AND INDEX_NAME = p_index_name
    ) THEN
        SET @ddl = CONCAT('CREATE INDEX ', p_index_def);
        PREPARE stmt FROM @ddl;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END$$

DELIMITER ;

CALL knig_add_file_event_column('target_dev', 'target_dev BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER pid');
CALL knig_add_file_event_column('target_ino', 'target_ino BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER target_dev');
CALL knig_add_file_event_column('blocked', 'blocked TINYINT(1) NOT NULL DEFAULT 0 AFTER target_ino');
CALL knig_add_file_event_column('actor_pid', 'actor_pid INT NOT NULL DEFAULT 0 AFTER blocked');
CALL knig_add_file_event_column('actor_ppid', 'actor_ppid INT NOT NULL DEFAULT 0 AFTER actor_pid');
CALL knig_add_file_event_column('actor_uid', 'actor_uid INT UNSIGNED NOT NULL DEFAULT 0 AFTER actor_ppid');
CALL knig_add_file_event_column('actor_euid', 'actor_euid INT UNSIGNED NOT NULL DEFAULT 0 AFTER actor_uid');
CALL knig_add_file_event_column('actor_sid', 'actor_sid INT NOT NULL DEFAULT 0 AFTER actor_euid');
CALL knig_add_file_event_column('actor_tty', 'actor_tty VARCHAR(32) NOT NULL DEFAULT '''' AFTER actor_sid');
CALL knig_add_file_event_column('actor_comm', 'actor_comm VARCHAR(16) NOT NULL DEFAULT '''' AFTER actor_tty');
CALL knig_add_file_event_column('actor_exe', 'actor_exe VARCHAR(256) NOT NULL DEFAULT '''' AFTER actor_comm');
CALL knig_add_file_event_column('actor_cmdline', 'actor_cmdline TEXT AFTER actor_exe');
CALL knig_add_file_event_column('actor_start_time_ns', 'actor_start_time_ns BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER actor_cmdline');
CALL knig_add_file_event_column('chain_depth', 'chain_depth TINYINT UNSIGNED NOT NULL DEFAULT 0 AFTER actor_start_time_ns');
CALL knig_add_file_event_column('chain_truncated', 'chain_truncated TINYINT(1) NOT NULL DEFAULT 0 AFTER chain_depth');

CALL knig_add_file_event_index('idx_file_events_target_inode', 'idx_file_events_target_inode ON file_events(target_dev, target_ino)');
CALL knig_add_file_event_index('idx_file_events_actor_pid', 'idx_file_events_actor_pid ON file_events(actor_pid)');

DROP PROCEDURE IF EXISTS knig_add_file_event_column;
DROP PROCEDURE IF EXISTS knig_add_file_event_index;

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
