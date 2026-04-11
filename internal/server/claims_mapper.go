package server

import (
	"saml-oidc-bridge/config"
	"saml-oidc-bridge/internal/oidc"
)

// ConfigClaimsMapper maps OIDC claims to SAML attributes based on configuration.
type ConfigClaimsMapper struct {
	nameIDClaim string
	attrMapping map[string]string
}

// NewConfigClaimsMapper creates a new claims mapper from configuration.
func NewConfigClaimsMapper(cfg *config.MappingConfig) *ConfigClaimsMapper {
	return &ConfigClaimsMapper{
		nameIDClaim: cfg.NameID,
		attrMapping: cfg.Attributes,
	}
}

// GetNameID extracts the NameID from user claims.
func (m *ConfigClaimsMapper) GetNameID(claims *oidc.UserClaims) string {
	return claims.GetClaimValue(m.nameIDClaim)
}

// MapAttributes maps OIDC claims to SAML attributes.
func (m *ConfigClaimsMapper) MapAttributes(claims *oidc.UserClaims) map[string]string {
	attributes := make(map[string]string)
	for samlAttr, oidcClaim := range m.attrMapping {
		value := claims.GetClaimValue(oidcClaim)
		if value != "" {
			attributes[samlAttr] = value
		}
	}
	return attributes
}
