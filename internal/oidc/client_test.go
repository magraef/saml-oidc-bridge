package oidc

import (
	"testing"
)

func TestGenerateState(t *testing.T) {
	state1, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() error = %v", err)
	}

	if len(state1) == 0 {
		t.Error("GenerateState() returned empty string")
	}

	// Generate another state to ensure randomness
	state2, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() error = %v", err)
	}

	if state1 == state2 {
		t.Error("GenerateState() returned same value twice, should be random")
	}

	// Verify it's valid base64
	if len(state1) < 40 {
		t.Errorf("GenerateState() returned short string: %d chars", len(state1))
	}
}

func TestUserClaims_GetClaimValue(t *testing.T) {
	claims := &UserClaims{
		Subject:           "user123",
		Email:             "test@example.com",
		EmailVerified:     true,
		PreferredUsername: "testuser",
		Name:              "Test User",
		GivenName:         "Test",
		FamilyName:        "User",
		Claims: map[string]interface{}{
			"custom_claim": "custom_value",
			"groups":       []string{"admin", "users"},
		},
	}

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "get email",
			key:      "email",
			expected: "test@example.com",
		},
		{
			name:     "get preferred_username",
			key:      "preferred_username",
			expected: "testuser",
		},
		{
			name:     "get name",
			key:      "name",
			expected: "Test User",
		},
		{
			name:     "get given_name",
			key:      "given_name",
			expected: "Test",
		},
		{
			name:     "get family_name",
			key:      "family_name",
			expected: "User",
		},
		{
			name:     "get subject",
			key:      "subject",
			expected: "user123",
		},
		{
			name:     "get sub",
			key:      "sub",
			expected: "user123",
		},
		{
			name:     "get custom claim",
			key:      "custom_claim",
			expected: "custom_value",
		},
		{
			name:     "get non-existent claim",
			key:      "non_existent",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.GetClaimValue(tt.key)
			if result != tt.expected {
				t.Errorf("GetClaimValue(%s) = %s, want %s", tt.key, result, tt.expected)
			}
		})
	}
}

func TestUserClaims_GetClaimValue_NonStringClaim(t *testing.T) {
	claims := &UserClaims{
		Claims: map[string]interface{}{
			"number_claim": 123,
			"bool_claim":   true,
			"array_claim":  []string{"a", "b"},
		},
	}

	// Non-string claims should return empty string
	if result := claims.GetClaimValue("number_claim"); result != "" {
		t.Errorf("Expected empty string for non-string claim, got %s", result)
	}
	if result := claims.GetClaimValue("bool_claim"); result != "" {
		t.Errorf("Expected empty string for non-string claim, got %s", result)
	}
	if result := claims.GetClaimValue("array_claim"); result != "" {
		t.Errorf("Expected empty string for non-string claim, got %s", result)
	}
}
