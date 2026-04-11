package saml

import (
	"net/http"
	"net/url"
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestGetRelayState(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idp := &IdP{
		logger: logger,
	}

	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "with relay state",
			url:      "https://example.com/saml/login?RelayState=test-state",
			expected: "test-state",
		},
		{
			name:     "without relay state",
			url:      "https://example.com/saml/login",
			expected: "",
		},
		{
			name:     "with empty relay state",
			url:      "https://example.com/saml/login?RelayState=",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedURL, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			req := &http.Request{
				URL: parsedURL,
			}

			result := idp.GetRelayState(req)
			if result != tt.expected {
				t.Errorf("GetRelayState() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestCreateResponse(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create certificate provider for signing
	certProvider, err := NewSelfSignedCertificateProvider(logger)
	if err != nil {
		t.Fatalf("Failed to create certificate provider: %v", err)
	}

	idp, err := NewIdP(
		"https://proxy.example.com",
		"https://proxy.example.com/saml/acs",
		"https://app.example.com",
		"https://app.example.com/saml/acs",
		certProvider,
		logger,
	)
	if err != nil {
		t.Fatalf("Failed to create IdP: %v", err)
	}

	requestID := "test-request-id"
	nameID := "user@example.com"
	attributes := map[string]string{
		"email":    "user@example.com",
		"username": "testuser",
		"name":     "Test User",
	}

	responseXML, err := idp.CreateResponse(requestID, nameID, attributes)
	if err != nil {
		t.Fatalf("CreateResponse() error = %v", err)
	}

	// Verify we got XML bytes
	if len(responseXML) == 0 {
		t.Fatal("CreateResponse returned empty XML")
	}

	// Verify XML contains expected elements (basic validation)
	responseStr := string(responseXML)

	if !contains(responseStr, requestID) {
		t.Errorf("Response XML does not contain InResponseTo=%s", requestID)
	}

	if !contains(responseStr, idp.spACSURL) {
		t.Errorf("Response XML does not contain Destination=%s", idp.spACSURL)
	}

	if !contains(responseStr, idp.entityID) {
		t.Errorf("Response XML does not contain Issuer=%s", idp.entityID)
	}

	if !contains(responseStr, "urn:oasis:names:tc:SAML:2.0:status:Success") {
		t.Error("Response XML does not contain Success status")
	}

	if !contains(responseStr, nameID) {
		t.Errorf("Response XML does not contain NameID=%s", nameID)
	}

	// Verify attributes are present
	if !contains(responseStr, "email") {
		t.Error("Response XML does not contain email attribute")
	}

	if !contains(responseStr, "user@example.com") {
		t.Error("Response XML does not contain email value")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestCreateResponse_NoAttributes(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create certificate provider for signing
	certProvider, err := NewSelfSignedCertificateProvider(logger)
	if err != nil {
		t.Fatalf("Failed to create certificate provider: %v", err)
	}

	idp, err := NewIdP(
		"https://proxy.example.com",
		"https://proxy.example.com/saml/acs",
		"https://app.example.com",
		"https://app.example.com/saml/acs",
		certProvider,
		logger,
	)
	if err != nil {
		t.Fatalf("Failed to create IdP: %v", err)
	}

	responseXML, err := idp.CreateResponse("test-id", "user@example.com", nil)
	if err != nil {
		t.Fatalf("CreateResponse() error = %v", err)
	}

	// Should still create valid XML response
	if len(responseXML) == 0 {
		t.Fatal("CreateResponse returned empty XML")
	}

	responseStr := string(responseXML)

	// Verify basic structure exists
	if !contains(responseStr, "user@example.com") {
		t.Error("Response XML does not contain NameID")
	}
}
