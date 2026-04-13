//go:generate sqlc generate

package storage

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store manages SQLite database connections and provides storage operations.
type Store struct {
	db      *sql.DB
	queries *Queries
	logger  *zap.Logger
	cancel  context.CancelFunc
}

// NewStore creates a new Store with initialized database and schema.
// It accepts a context that will be used to manage the cleanup goroutine lifecycle.
func NewStore(ctx context.Context, databasePath string, logger *zap.Logger) (*Store, error) {
	// Open database connection
	db, err := sql.Open("sqlite", databasePath)
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

	// Create cancellable context for cleanup goroutine
	cleanupCtx, cancel := context.WithCancel(ctx)

	store := &Store{
		db:      db,
		queries: New(db),
		logger:  logger,
		cancel:  cancel,
	}

	// Run migrations
	if err := store.migrate(); err != nil {
		cancel()
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	logger.Info("Storage initialized",
		zap.String("database", databasePath),
		zap.String("driver", "sqlite"),
	)

	// Start cleanup goroutine
	go store.cleanupExpiredRequests(cleanupCtx)

	return store, nil
}

// migrate runs database migrations using golang-migrate.
func (s *Store) migrate() error {
	// Create source driver from embedded filesystem
	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to create migration source: %w", err)
	}

	// Create database driver
	driver, err := sqlite3.WithInstance(s.db, &sqlite3.Config{})
	if err != nil {
		return fmt.Errorf("failed to create database driver: %w", err)
	}

	// Create migrate instance
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "sqlite3", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	// Run migrations
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
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

// CreateSession stores a new session
func (s *Store) CreateSession(ctx context.Context, arg CreateSessionParams) error {
	return s.queries.CreateSession(ctx, arg)
}

// GetSession retrieves a session by session index
func (s *Store) GetSession(ctx context.Context, sessionIndex string) (Session, error) {
	return s.queries.GetSession(ctx, sessionIndex)
}

// DeleteSession removes a session
func (s *Store) DeleteSession(ctx context.Context, sessionIndex string) error {
	return s.queries.DeleteSession(ctx, sessionIndex)
}

// cleanupExpiredRequests periodically removes expired SAML requests and sessions.
func (s *Store) cleanupExpiredRequests(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	s.logger.Debug("Started cleanup goroutine for expired SAML requests and sessions")

	for {
		select {
		case <-ctx.Done():
			s.logger.Debug("Cleanup goroutine stopped")
			return
		case <-ticker.C:
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			now := time.Now().Unix()

			// Cleanup expired SAML requests
			if err := s.CleanupExpired(cleanupCtx, now); err != nil {
				s.logger.Error("Failed to cleanup expired requests", zap.Error(err))
			} else {
				s.logger.Debug("Cleaned up expired requests")
			}

			// Cleanup expired sessions
			if err := s.queries.DeleteExpiredSessions(cleanupCtx, now); err != nil {
				s.logger.Error("Failed to cleanup expired sessions", zap.Error(err))
			} else {
				s.logger.Debug("Cleaned up expired sessions")
			}

			cancel()
		}
	}
}

// Close gracefully shuts down the store by stopping the cleanup goroutine
// and closing the database connection.
func (s *Store) Close() error {
	s.logger.Debug("Shutting down storage")

	// Stop cleanup goroutine
	if s.cancel != nil {
		s.cancel()
	}

	// Close database connection
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
