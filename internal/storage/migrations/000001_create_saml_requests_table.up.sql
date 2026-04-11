-- Create SAML requests table
CREATE TABLE IF NOT EXISTS saml_requests (
    id TEXT PRIMARY KEY,
    relay_state TEXT NOT NULL,
    sp_acs_url TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- Create index on expires_at for efficient cleanup queries
CREATE INDEX IF NOT EXISTS idx_saml_requests_expires_at ON saml_requests(expires_at);
