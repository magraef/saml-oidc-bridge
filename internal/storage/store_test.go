package storage

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"
)

func TestStoreMigrations(t *testing.T) {
	// Create temporary database file
	tmpDB := "/tmp/test-migrations.db"
	defer os.Remove(tmpDB)

	logger := zap.NewNop()
	ctx := context.Background()

	// Create store - this should run migrations
	store, err := NewStore(ctx, tmpDB, nil, logger)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Verify table exists by trying to insert data
	err = store.StoreSAMLRequest(ctx, "test-id", "test-relay", "https://test.example.com/acs")
	if err != nil {
		t.Fatalf("Failed to store SAML request: %v", err)
	}

	// Verify we can retrieve the data
	relayState, spACSURL, err := store.GetSAMLRequestData(ctx, "test-id")
	if err != nil {
		t.Fatalf("Failed to get SAML request: %v", err)
	}

	if relayState != "test-relay" {
		t.Errorf("Expected relay state 'test-relay', got '%s'", relayState)
	}

	if spACSURL != "https://test.example.com/acs" {
		t.Errorf("Expected SP ACS URL 'https://test.example.com/acs', got '%s'", spACSURL)
	}

	// Verify we can delete the data
	err = store.DeleteSAMLRequest(ctx, "test-id")
	if err != nil {
		t.Fatalf("Failed to delete SAML request: %v", err)
	}

	// Verify data is deleted
	_, _, err = store.GetSAMLRequestData(ctx, "test-id")
	if err == nil {
		t.Error("Expected error when getting deleted request, got nil")
	}
}

func TestStoreMigrationsIdempotent(t *testing.T) {
	// Create temporary database file
	tmpDB := "/tmp/test-migrations-idempotent.db"
	defer os.Remove(tmpDB)

	logger := zap.NewNop()
	ctx := context.Background()

	// Create store first time
	store1, err := NewStore(ctx, tmpDB, nil, logger)
	if err != nil {
		t.Fatalf("Failed to create store first time: %v", err)
	}
	store1.Close()

	// Create store second time - migrations should be idempotent
	store2, err := NewStore(ctx, tmpDB, nil, logger)
	if err != nil {
		t.Fatalf("Failed to create store second time: %v", err)
	}
	defer store2.Close()

	// Verify store works after reopening
	err = store2.StoreSAMLRequest(ctx, "test-id-2", "test-relay-2", "https://test2.example.com/acs")
	if err != nil {
		t.Fatalf("Failed to store SAML request after reopening: %v", err)
	}
}

func TestStoreSessionEncryption(t *testing.T) {
	// Create temporary database file
	tmpDB := "/tmp/test-session-encryption.db"
	defer os.Remove(tmpDB)

	logger := zap.NewNop()
	ctx := context.Background()

	// Generate a test encryption key (32 bytes)
	encryptionKey := []byte("12345678901234567890123456789012")

	// Create store with encryption enabled
	store, err := NewStore(ctx, tmpDB, encryptionKey, logger)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Create a session with an ID token
	testIDToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
	sessionParams := CreateSessionParams{
		SessionIndex: "test-session-123",
		NameID:       "user@example.com",
		IDToken:      testIDToken,
		SpEntityID:   "https://sp.example.com",
		ExpiresAt:    9999999999,
	}

	// Store the session
	err = store.CreateSession(ctx, sessionParams)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Verify the ID token is encrypted in the database
	var storedToken string
	err = store.db.QueryRow("SELECT id_token FROM sessions WHERE session_index = ?", "test-session-123").Scan(&storedToken)
	if err != nil {
		t.Fatalf("Failed to query stored token: %v", err)
	}

	// Stored token should be different from original (encrypted)
	if storedToken == testIDToken {
		t.Error("ID token should be encrypted in database, but it matches plaintext")
	}

	// Retrieve the session - should decrypt automatically
	session, err := store.GetSession(ctx, "test-session-123")
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	// Decrypted token should match original
	if session.IDToken != testIDToken {
		t.Errorf("Decrypted ID token doesn't match original.\nWant: %s\nGot:  %s", testIDToken, session.IDToken)
	}

	// Verify other fields
	if session.NameID != "user@example.com" {
		t.Errorf("Expected NameID 'user@example.com', got '%s'", session.NameID)
	}
}

func TestStoreSessionWithoutEncryption(t *testing.T) {
	// Create temporary database file
	tmpDB := "/tmp/test-session-no-encryption.db"
	defer os.Remove(tmpDB)

	logger := zap.NewNop()
	ctx := context.Background()

	// Create store without encryption (nil key)
	store, err := NewStore(ctx, tmpDB, nil, logger)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Create a session with an ID token
	testIDToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
	sessionParams := CreateSessionParams{
		SessionIndex: "test-session-456",
		NameID:       "user@example.com",
		IDToken:      testIDToken,
		SpEntityID:   "https://sp.example.com",
		ExpiresAt:    9999999999,
	}

	// Store the session
	err = store.CreateSession(ctx, sessionParams)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Verify the ID token is stored in plaintext
	var storedToken string
	err = store.db.QueryRow("SELECT id_token FROM sessions WHERE session_index = ?", "test-session-456").Scan(&storedToken)
	if err != nil {
		t.Fatalf("Failed to query stored token: %v", err)
	}

	// Without encryption, stored token should match original
	if storedToken != testIDToken {
		t.Errorf("Without encryption, stored token should match original.\nWant: %s\nGot:  %s", testIDToken, storedToken)
	}

	// Retrieve the session
	session, err := store.GetSession(ctx, "test-session-456")
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	// Retrieved token should match original
	if session.IDToken != testIDToken {
		t.Errorf("Retrieved ID token doesn't match original.\nWant: %s\nGot:  %s", testIDToken, session.IDToken)
	}
}
