package server

import (
	"context"
	"net/http"

	"saml-oidc-bridge/internal/oidc"

	"github.com/crewjam/saml"
)

// OIDCAuthenticator handles OpenID Connect authentication.
type OIDCAuthenticator interface {
	GetAuthorizationURL(state string) string
	ExchangeCodeForToken(ctx context.Context, code string) (*oidc.UserClaims, error)
}

// SAMLRequestParser parses SAML authentication requests.
type SAMLRequestParser interface {
	ParseAuthnRequest(r *http.Request) (*saml.AuthnRequest, error)
	GetRelayState(r *http.Request) string
}

// SAMLResponseCreator creates SAML responses.
type SAMLResponseCreator interface {
	CreateResponse(requestID, nameID string, attributes map[string]string) ([]byte, error)
}

// SAMLMetadataProvider provides SAML metadata.
type SAMLMetadataProvider interface {
	GetMetadata() (*saml.EntityDescriptor, error)
}

// SAMLRequestStore stores and retrieves SAML requests.
type SAMLRequestStore interface {
	StoreSAMLRequest(ctx context.Context, requestID, relayState, spACSURL string) error
	GetSAMLRequestData(ctx context.Context, requestID string) (relayState, spACSURL string, err error)
	DeleteSAMLRequest(ctx context.Context, requestID string) error
}

// ExpiredRequestCleaner cleans up expired requests.
type ExpiredRequestCleaner interface {
	CleanupExpired(ctx context.Context, expiryTime int64) error
}

// ClaimsMapper maps OIDC claims to SAML attributes.
type ClaimsMapper interface {
	GetNameID(claims *oidc.UserClaims) string
	MapAttributes(claims *oidc.UserClaims) map[string]string
}
