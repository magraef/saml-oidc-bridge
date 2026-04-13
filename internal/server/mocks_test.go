package server

import (
	"context"
	"net/http"

	"saml-oidc-bridge/internal/oidc"

	"github.com/crewjam/saml"
)

// Mock implementations for testing - following Go best practices:
// - Small, focused interfaces
// - Declared where they're used (in server package)
// - Simple implementations without "adapter" naming

// mockOIDCAuth is a test double for OIDCAuthenticator
type mockOIDCAuth struct {
	authURL string
	claims  *oidc.UserClaims
	err     error
}

func (m *mockOIDCAuth) GetAuthorizationURL(state string) string {
	if m.authURL != "" {
		return m.authURL
	}
	return "https://mock-oidc.example.com/authorize?state=" + state
}

func (m *mockOIDCAuth) ExchangeCodeForToken(ctx context.Context, code string) (*oidc.UserClaims, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.claims != nil {
		return m.claims, nil
	}
	return &oidc.UserClaims{
		Subject: "mock-user-123",
		Email:   "user@example.com",
		Name:    "Mock User",
		Claims:  map[string]interface{}{"email": "user@example.com"},
	}, nil
}

// mockSAMLParser is a test double for SAMLRequestParser
type mockSAMLParser struct {
	request    *saml.AuthnRequest
	relayState string
	err        error
}

func (m *mockSAMLParser) ParseAuthnRequest(r *http.Request) (*saml.AuthnRequest, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.request != nil {
		return m.request, nil
	}
	return &saml.AuthnRequest{
		ID: "mock-request-id",
		Issuer: &saml.Issuer{
			Value: "https://sp.example.com",
		},
		AssertionConsumerServiceURL: "https://sp.example.com/acs",
	}, nil
}

func (m *mockSAMLParser) GetRelayState(r *http.Request) string {
	return m.relayState
}

// mockSAMLResponder is a test double for SAMLResponseCreator
type mockSAMLResponder struct {
	response []byte
	err      error
}

func (m *mockSAMLResponder) CreateResponse(requestID, nameID string, attributes map[string]string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.response != nil {
		return m.response, nil
	}
	return []byte("<saml:Response>mock response</saml:Response>"), nil
}

// mockSAMLMetadata is a test double for SAMLMetadataProvider
type mockSAMLMetadata struct {
	metadata *saml.EntityDescriptor
	err      error
}

func (m *mockSAMLMetadata) GetMetadata() (*saml.EntityDescriptor, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.metadata != nil {
		return m.metadata, nil
	}
	return &saml.EntityDescriptor{
		EntityID: "https://idp.example.com",
	}, nil
}

// mockSAMLRequestStore is a test double for SAMLRequestStore
type mockSAMLRequestStore struct {
	relayState string
	spACSURL   string
	err        error
}

func (m *mockSAMLRequestStore) StoreSAMLRequest(ctx context.Context, requestID, relayState, spACSURL string) error {
	return m.err
}

func (m *mockSAMLRequestStore) GetSAMLRequestData(ctx context.Context, requestID string) (relayState, spACSURL string, err error) {
	if m.err != nil {
		return "", "", m.err
	}
	return m.relayState, m.spACSURL, nil
}

func (m *mockSAMLRequestStore) DeleteSAMLRequest(ctx context.Context, requestID string) error {
	return m.err
}

// mockRequestCleaner is a test double for ExpiredRequestCleaner
type mockRequestCleaner struct {
	err error
}

func (m *mockRequestCleaner) CleanupExpired(ctx context.Context, expiryTime int64) error {
	return m.err
}

// mockClaimsMapper is a test double for ClaimsMapper
type mockClaimsMapper struct {
	nameID     string
	attributes map[string]string
}

func (m *mockClaimsMapper) GetNameID(claims *oidc.UserClaims) string {
	if m.nameID != "" {
		return m.nameID
	}
	return claims.Email
}

func (m *mockClaimsMapper) MapAttributes(claims *oidc.UserClaims) map[string]string {
	if m.attributes != nil {
		return m.attributes
	}
	return map[string]string{
		"email": claims.Email,
		"name":  claims.Name,
	}
}

// mockStore is a test double for storage.Store
type mockStore struct {
	createSessionErr error
	getSessionErr    error
	deleteSessionErr error
}

func (m *mockStore) CreateSession(ctx context.Context, arg interface{}) error {
	return m.createSessionErr
}

func (m *mockStore) GetSession(ctx context.Context, sessionIndex string) (interface{}, error) {
	if m.getSessionErr != nil {
		return nil, m.getSessionErr
	}
	return struct {
		SessionIndex string
		NameID       string
		IDToken      string
		SpEntityID   string
		CreatedAt    int64
		ExpiresAt    int64
	}{
		SessionIndex: sessionIndex,
		NameID:       "user@example.com",
		IDToken:      "mock-id-token",
		SpEntityID:   "https://sp.example.com",
		CreatedAt:    0,
		ExpiresAt:    0,
	}, nil
}

func (m *mockStore) DeleteSession(ctx context.Context, sessionIndex string) error {
	return m.deleteSessionErr
}

func (m *mockStore) Close() error {
	return nil
}
