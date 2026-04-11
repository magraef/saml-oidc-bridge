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

	// Create store - this should run migrations
	store, err := NewStore(tmpDB, logger)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Verify table exists by trying to insert data
	ctx := context.Background()
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

	// Create store first time
	store1, err := NewStore(tmpDB, logger)
	if err != nil {
		t.Fatalf("Failed to create store first time: %v", err)
	}
	store1.Close()

	// Create store second time - migrations should be idempotent
	store2, err := NewStore(tmpDB, logger)
	if err != nil {
		t.Fatalf("Failed to create store second time: %v", err)
	}
	defer store2.Close()

	// Verify store works after reopening
	ctx := context.Background()
	err = store2.StoreSAMLRequest(ctx, "test-id-2", "test-relay-2", "https://test2.example.com/acs")
	if err != nil {
		t.Fatalf("Failed to store SAML request after reopening: %v", err)
	}
}
