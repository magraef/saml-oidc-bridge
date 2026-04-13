package storage

import (
	"crypto/rand"
	"testing"
)

func TestEncryptor_EncryptDecrypt(t *testing.T) {
	// Generate a random 32-byte key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encryptor, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple text",
			plaintext: "hello world",
		},
		{
			name:      "ID token",
			plaintext: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		},
		{
			name:      "empty string",
			plaintext: "",
		},
		{
			name:      "unicode text",
			plaintext: "Hello 世界 🌍",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := encryptor.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Empty plaintext should return empty ciphertext
			if tt.plaintext == "" {
				if ciphertext != "" {
					t.Errorf("Expected empty ciphertext for empty plaintext, got %q", ciphertext)
				}
				return
			}

			// Ciphertext should be different from plaintext
			if ciphertext == tt.plaintext {
				t.Error("Ciphertext should not equal plaintext")
			}

			// Decrypt
			decrypted, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Decrypted should match original
			if decrypted != tt.plaintext {
				t.Errorf("Decrypted text doesn't match original.\nWant: %q\nGot:  %q", tt.plaintext, decrypted)
			}
		})
	}
}

func TestEncryptor_DifferentNonces(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encryptor, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plaintext := "test message"

	// Encrypt same plaintext twice
	ciphertext1, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("First encrypt failed: %v", err)
	}

	ciphertext2, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Second encrypt failed: %v", err)
	}

	// Ciphertexts should be different (different nonces)
	if ciphertext1 == ciphertext2 {
		t.Error("Encrypting same plaintext twice should produce different ciphertexts")
	}

	// Both should decrypt to same plaintext
	decrypted1, err := encryptor.Decrypt(ciphertext1)
	if err != nil {
		t.Fatalf("First decrypt failed: %v", err)
	}

	decrypted2, err := encryptor.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("Second decrypt failed: %v", err)
	}

	if decrypted1 != plaintext || decrypted2 != plaintext {
		t.Error("Both decryptions should produce original plaintext")
	}
}

func TestNewEncryptor_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"too short", 16},
		{"too long", 64},
		{"empty", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := NewEncryptor(key)
			if err == nil {
				t.Error("Expected error for invalid key size, got nil")
			}
		})
	}
}

func TestEncryptor_DecryptInvalidData(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encryptor, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
	}{
		{
			name:       "invalid base64",
			ciphertext: "not-valid-base64!!!",
		},
		{
			name:       "too short",
			ciphertext: "YWJj", // "abc" in base64
		},
		{
			name:       "corrupted data",
			ciphertext: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptor.Decrypt(tt.ciphertext)
			if err == nil {
				t.Error("Expected error for invalid ciphertext, got nil")
			}
		})
	}
}
