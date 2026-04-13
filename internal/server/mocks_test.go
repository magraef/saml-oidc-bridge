package server

import (
	"context"

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
