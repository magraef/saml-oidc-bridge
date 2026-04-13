-- Create sessions table for tracking active SAML sessions
CREATE TABLE IF NOT EXISTS sessions (
    session_index TEXT PRIMARY KEY,
    name_id TEXT NOT NULL,
    id_token TEXT NOT NULL,
    sp_entity_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- Create indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_name_id ON sessions(name_id);
