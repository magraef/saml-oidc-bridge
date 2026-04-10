package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"saml-oidc-bridge/config"

	"go.uber.org/zap/zaptest"
)

func TestHandleHealth(t *testing.T) {
	server := &Server{}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	body := w.Body.String()
	expected := `{"status":"healthy"}`
	if body != expected {
		t.Errorf("Expected body %s, got %s", expected, body)
	}
}

func TestSetAndGetSession(t *testing.T) {
	server := &Server{
		config: &config.Config{
			Session: config.SessionConfig{
				CookieName:   "test-session",
				CookieSecure: false,
			},
		},
	}

	// Test setting session
	w := httptest.NewRecorder()
	sessionData := sessionData{
		RequestID:  "test-request-id",
		RelayState: "test-relay-state",
		State:      "test-state",
	}

	err := server.setSession(w, sessionData)
	if err != nil {
		t.Fatalf("setSession() error = %v", err)
	}

	// Verify cookie was set
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("No cookies set")
	}

	cookie := cookies[0]
	if cookie.Name != "test-session" {
		t.Errorf("Expected cookie name test-session, got %s", cookie.Name)
	}
	if !cookie.HttpOnly {
		t.Error("Expected HttpOnly cookie")
	}

	// Test getting session
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	retrievedSession, err := server.getSession(req)
	if err != nil {
		t.Fatalf("getSession() error = %v", err)
	}

	if retrievedSession.RequestID != sessionData.RequestID {
		t.Errorf("RequestID = %s, want %s", retrievedSession.RequestID, sessionData.RequestID)
	}
	if retrievedSession.RelayState != sessionData.RelayState {
		t.Errorf("RelayState = %s, want %s", retrievedSession.RelayState, sessionData.RelayState)
	}
	if retrievedSession.State != sessionData.State {
		t.Errorf("State = %s, want %s", retrievedSession.State, sessionData.State)
	}
}

func TestGetSession_NoCookie(t *testing.T) {
	server := &Server{
		config: &config.Config{
			Session: config.SessionConfig{
				CookieName: "test-session",
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := server.getSession(req)
	if err == nil {
		t.Error("Expected error when no cookie present")
	}
}

func TestClearSession(t *testing.T) {
	server := &Server{
		config: &config.Config{
			Session: config.SessionConfig{
				CookieName: "test-session",
			},
		},
	}

	w := httptest.NewRecorder()
	server.clearSession(w)

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("No cookies set")
	}

	cookie := cookies[0]
	if cookie.MaxAge != -1 {
		t.Errorf("Expected MaxAge -1 for deletion, got %d", cookie.MaxAge)
	}
	if cookie.Value != "" {
		t.Errorf("Expected empty value for deletion, got %s", cookie.Value)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := &Server{
		logger: logger,
	}

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Wrap with logging middleware
	handler := server.loggingMiddleware(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body := w.Body.String()
	if body != "test response" {
		t.Errorf("Expected body 'test response', got %s", body)
	}
}
