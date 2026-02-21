CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    description VARCHAR(64) NOT NULL,
    credential_id BLOB NOT NULL,
    public_key BLOB NOT NULL,
    aaguid VARCHAR(36) DEFAULT NULL,
    attestation_type VARCHAR(32) DEFAULT NULL,
    attachment VARCHAR(16) DEFAULT NULL,
    transports VARCHAR(128) DEFAULT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    clone_warning INTEGER NOT NULL DEFAULT 0,
    user_verified INTEGER NOT NULL DEFAULT 0,
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_webauthn_user_cred ON webauthn_credentials (user_id, credential_id);
CREATE INDEX IF NOT EXISTS ix_webauthn_user ON webauthn_credentials (user_id);
