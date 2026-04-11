//go:generate sqlc generate

package storage

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

// Store manages SQLite database connections and provides storage operations.
type Store struct {
	db      *sql.DB
	queries *Queries
	logger  *zap.Logger
}

// NewStore creates a new Store with initialized database and schema.
func NewStore(databasePath string, logger *zap.Logger) (*Store, error) {
	// Open database connection
	db, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &Store{
		db:      db,
		queries: New(db),
		logger:  logger,
	}

	// Run migrations
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	logger.Info("Storage initialized",
		zap.String("database", databasePath),
		zap.String("driver", "sqlite3"),
	)

	return store, nil
}

// migrate runs database migrations.
func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS saml_requests (
		id TEXT PRIMARY KEY,
		relay_state TEXT NOT NULL,
		sp_acs_url TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_saml_requests_expires_at ON saml_requests(expires_at);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	s.logger.Debug("Database schema migrated successfully")
	return nil
}

// StoreSAMLRequest stores a SAML request.
func (s *Store) StoreSAMLRequest(ctx context.Context, requestID, relayState, spACSURL string) error {
	return s.queries.CreateSAMLRequest(ctx, CreateSAMLRequestParams{
		ID:         requestID,
		RelayState: relayState,
		SpAcsUrl:   spACSURL,
	})
}

// GetSAMLRequestData retrieves a SAML request.
func (s *Store) GetSAMLRequestData(ctx context.Context, requestID string) (relayState, spACSURL string, err error) {
	req, err := s.queries.GetSAMLRequest(ctx, requestID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get SAML request: %w", err)
	}
	return req.RelayState, req.SpAcsUrl, nil
}

// DeleteSAMLRequest deletes a SAML request.
func (s *Store) DeleteSAMLRequest(ctx context.Context, requestID string) error {
	return s.queries.DeleteSAMLRequest(ctx, requestID)
}

// CleanupExpired removes expired SAML requests.
func (s *Store) CleanupExpired(ctx context.Context, expiryTime int64) error {
	return s.queries.DeleteExpiredRequests(ctx, expiryTime)
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db != nil {
		s.logger.Debug("Closing database connection")
		return s.db.Close()
	}
	return nil
}

// DB returns the underlying database connection for advanced use cases.
func (s *Store) DB() *sql.DB {
	return s.db
}
