package server

import (
	"saml-oidc-bridge/config"
	"saml-oidc-bridge/internal/oidc"

	"go.uber.org/zap"
)

// ConfigClaimsMapper maps OIDC claims to SAML attributes based on configuration.
type ConfigClaimsMapper struct {
	nameIDClaim string
	attrMapping map[string]string
	logger      *zap.Logger
}

// NewConfigClaimsMapper creates a new claims mapper from configuration.
func NewConfigClaimsMapper(cfg *config.MappingConfig, logger *zap.Logger) *ConfigClaimsMapper {
	return &ConfigClaimsMapper{
		nameIDClaim: cfg.NameID,
		attrMapping: cfg.Attributes,
		logger:      logger,
	}
}

// GetNameID extracts the NameID from user claims.
func (m *ConfigClaimsMapper) GetNameID(claims *oidc.UserClaims) string {
	nameID := claims.GetClaimValue(m.nameIDClaim)

	if m.logger != nil {
		m.logger.Debug("Extracting NameID from claims",
			zap.String("claim_name", m.nameIDClaim),
			zap.String("name_id", nameID),
		)
	}

	return nameID
}

// MapAttributes maps OIDC claims to SAML attributes.
func (m *ConfigClaimsMapper) MapAttributes(claims *oidc.UserClaims) map[string]string {
	attributes := make(map[string]string)
	mappingDetails := make([]zap.Field, 0, len(m.attrMapping)*2)

	for samlAttr, oidcClaim := range m.attrMapping {
		value := claims.GetClaimValue(oidcClaim)
		if value != "" {
			attributes[samlAttr] = value
			mappingDetails = append(mappingDetails,
				zap.String("saml_attr_"+samlAttr, oidcClaim+"="+value),
			)
		} else {
			mappingDetails = append(mappingDetails,
				zap.String("saml_attr_"+samlAttr+"_missing", oidcClaim),
			)
		}
	}

	if m.logger != nil {
		m.logger.Debug("Mapped OIDC claims to SAML attributes",
			append([]zap.Field{
				zap.Int("total_mappings", len(m.attrMapping)),
				zap.Int("successful_mappings", len(attributes)),
			}, mappingDetails...)...,
		)
	}

	return attributes
}
