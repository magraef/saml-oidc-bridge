package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"saml-oidc-bridge/internal/oidc"

	"go.uber.org/zap"
)

func TestHandleMetadata(t *testing.T) {
	// Create mock SAML metadata provider
	mockMetadata := &mockSAMLMetadata{}

	// Create server with mocked dependencies
	server := NewServerWithDependencies(
		nil, // OIDC not needed for metadata
		nil, // Parser not needed
		nil, // Responder not needed
		mockMetadata,
		nil, // Request store not needed
		nil, // Cleaner not needed
		nil, // Claims mapper not needed
		nil, // DB not needed
		zap.NewNop(),
		"test-cookie",
		false,
		"https://sp.example.com",
		"https://sp.example.com/acs",
		80,
	)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/metadata", nil)
	w := httptest.NewRecorder()

	// Call handler
	server.handleMetadata(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/xml" {
		t.Errorf("Expected Content-Type application/xml, got %s", contentType)
	}

	body := w.Body.String()
	if body == "" {
		t.Error("Expected non-empty response body")
	}
}

func TestHandleOIDCCallback_Success(t *testing.T) {
	// Create mocks
	mockOIDC := &mockOIDCAuth{
		claims: &oidc.UserClaims{
			Subject: "user-123",
			Email:   "test@example.com",
			Name:    "Test User",
			Claims: map[string]interface{}{
				"email": "test@example.com",
				"name":  "Test User",
			},
		},
	}

	mockResponder := &mockSAMLResponder{
		response: []byte("<saml:Response>test</saml:Response>"),
	}

	mockStore := &mockSAMLRequestStore{
		relayState: "",
		spACSURL:   "https://sp.example.com/acs",
	}

	mockMapper := &mockClaimsMapper{}

	// Create server with mocked dependencies
	server := NewServerWithDependencies(
		mockOIDC,
		nil, // Parser not needed
		mockResponder,
		nil, // Metadata not needed
		mockStore,
		nil, // Cleaner not needed
		mockMapper,
		nil,
		zap.NewNop(),
		"test-cookie",
		false,
		"https://sp.example.com",
		"https://sp.example.com/acs",
		80,
	)

	// Use a valid state (base64 encoded, at least 22 chars)
	validState := "dGVzdC1zdGF0ZS12YWxpZC1sb25nLWVub3VnaA=="

	// Create test request with session cookie
	req := httptest.NewRequest(http.MethodGet, "/oidc/callback?code=test-code&state="+validState, nil)

	// Add session cookie
	sessionData := sessionData{
		RequestID:  "test-request-id",
		RelayState: "",
		State:      validState,
	}
	w := httptest.NewRecorder()
	server.setSession(w, sessionData)

	// Get the cookie and add it to the request
	cookies := w.Result().Cookies()
	if len(cookies) > 0 {
		req.AddCookie(cookies[0])
	}

	// Reset recorder for actual test
	w = httptest.NewRecorder()

	// Call handler
	server.handleOIDCCallback(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Verify HTML response contains form
	body := w.Body.String()
	if body == "" {
		t.Error("Expected non-empty response body")
	}
}

func TestHandleHealth(t *testing.T) {
	// Create minimal server
	server := NewServerWithDependencies(
		nil, nil, nil, nil, nil, nil, nil, nil,
		zap.NewNop(),
		"test-cookie",
		false,
		"https://sp.example.com",
		"https://sp.example.com/acs",
		80,
	)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	// Call handler
	server.handleHealth(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	expectedBody := `{"status":"healthy"}`
	if w.Body.String() != expectedBody {
		t.Errorf("Expected body %s, got %s", expectedBody, w.Body.String())
	}
}
