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
	idp := &IdP{
		entityID:   "https://proxy.example.com",
		spEntityID: "https://app.example.com",
		spACSURL:   "https://app.example.com/saml/acs",
		logger:     logger,
	}

	requestID := "test-request-id"
	nameID := "user@example.com"
	attributes := map[string]string{
		"email":    "user@example.com",
		"username": "testuser",
		"name":     "Test User",
	}

	response, err := idp.CreateResponse(requestID, nameID, attributes)
	if err != nil {
		t.Fatalf("CreateResponse() error = %v", err)
	}

	// Verify response structure
	if response.InResponseTo != requestID {
		t.Errorf("InResponseTo = %s, want %s", response.InResponseTo, requestID)
	}

	if response.Destination != idp.spACSURL {
		t.Errorf("Destination = %s, want %s", response.Destination, idp.spACSURL)
	}

	if response.Issuer.Value != idp.entityID {
		t.Errorf("Issuer = %s, want %s", response.Issuer.Value, idp.entityID)
	}

	if response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		t.Errorf("StatusCode = %s, want Success", response.Status.StatusCode.Value)
	}

	// Verify assertion
	if response.Assertion == nil {
		t.Fatal("Assertion is nil")
	}

	if response.Assertion.Subject.NameID.Value != nameID {
		t.Errorf("NameID = %s, want %s", response.Assertion.Subject.NameID.Value, nameID)
	}

	// Verify attributes
	if len(response.Assertion.AttributeStatements) == 0 {
		t.Fatal("No attribute statements")
	}

	attrs := response.Assertion.AttributeStatements[0].Attributes
	if len(attrs) != len(attributes) {
		t.Errorf("Expected %d attributes, got %d", len(attributes), len(attrs))
	}

	// Verify specific attributes
	foundEmail := false
	for _, attr := range attrs {
		if attr.Name == "email" {
			foundEmail = true
			if len(attr.Values) == 0 || attr.Values[0].Value != "user@example.com" {
				t.Errorf("Email attribute value incorrect")
			}
		}
	}
	if !foundEmail {
		t.Error("Email attribute not found")
	}
}

func TestCreateResponse_NoAttributes(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idp := &IdP{
		entityID:   "https://proxy.example.com",
		spEntityID: "https://app.example.com",
		spACSURL:   "https://app.example.com/saml/acs",
		logger:     logger,
	}

	response, err := idp.CreateResponse("test-id", "user@example.com", nil)
	if err != nil {
		t.Fatalf("CreateResponse() error = %v", err)
	}

	// Should still create response without attributes
	if response.Assertion == nil {
		t.Fatal("Assertion is nil")
	}

	if len(response.Assertion.AttributeStatements) != 0 {
		t.Errorf("Expected no attribute statements, got %d", len(response.Assertion.AttributeStatements))
	}
}

func TestSignResponse(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idp := &IdP{
		entityID: "https://proxy.example.com",
		logger:   logger,
	}

	response, err := idp.CreateResponse("test-id", "user@example.com", nil)
	if err != nil {
		t.Fatalf("CreateResponse() error = %v", err)
	}

	// SignResponse should not error (even though it's simplified for PoC)
	err = idp.SignResponse(response)
	if err != nil {
		t.Errorf("SignResponse() error = %v", err)
	}
}
