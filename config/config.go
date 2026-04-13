package config

import (
	"fmt"
	"os"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Config represents the complete application configuration
type Config struct {
	OIDC    OIDCConfig
	SAML    SAMLConfig
	SP      SPConfig
	Mapping MappingConfig
	Session SessionConfig
	Server  ServerConfig
	Storage StorageConfig
}

// OIDCConfig contains OpenID Connect provider settings
type OIDCConfig struct {
	IssuerURL    string   `env:"OIDC_ISSUER_URL"`
	ClientID     string   `env:"OIDC_CLIENT_ID"`
	ClientSecret string   `env:"OIDC_CLIENT_SECRET"`
	Scopes       []string `env:"OIDC_SCOPES" envSeparator:"," envDefault:"openid,profile,email"`

	// Derived field (populated from IDP_URL during validation)
	RedirectURL string
}

// SAMLConfig contains SAML IdP settings for this proxy
type SAMLConfig struct {
	// Base URL for the IdP (e.g., https://saml-bridge.example.com)
	// All SAML endpoints will be derived from this URL:
	// - Entity ID: IDP_URL
	// - Metadata: IDP_URL/metadata
	// - ACS URL: IDP_URL/saml/acs
	// - Login: IDP_URL/saml/login
	// - Logout: IDP_URL/saml/logout
	IDPURL          string `env:"IDP_URL"`
	CertificatePath string `env:"SAML_CERTIFICATE_PATH"`
	PrivateKeyPath  string `env:"SAML_PRIVATE_KEY_PATH"`

	// Derived fields (populated from IDP_URL during validation)
	EntityID string
	ACSURL   string
}

// SPConfig contains the Service Provider (application) settings
type SPConfig struct {
	EntityID string `env:"SP_ENTITY_ID"`
	ACSURL   string `env:"SP_ACS_URL"`
}

// MappingConfig defines how OIDC claims map to SAML attributes
type MappingConfig struct {
	NameID     string            `env:"MAPPING_NAME_ID"`
	Attributes map[string]string `env:"MAPPING_ATTRIBUTES"`
}

// SessionConfig contains session cookie settings
type SessionConfig struct {
	CookieSecret string `env:"SESSION_COOKIE_SECRET"`
	CookieSecure bool   `env:"SESSION_COOKIE_SECURE" envDefault:"false"`
	CookieName   string `env:"SESSION_COOKIE_NAME" envDefault:"saml-oidc-bridge-session"`
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	Address string `env:"SERVER_ADDRESS" envDefault:":8080"`
	Port    int    `env:"PORT"`
	Debug   bool   `env:"DEBUG" envDefault:"false"`
}

// StorageConfig contains database settings
type StorageConfig struct {
	DatabasePath  string `env:"STORAGE_DATABASE_PATH" envDefault:"./saml-oidc-bridge.db"`
	EncryptionKey string `env:"STORAGE_ENCRYPTION_KEY"` // 32-byte hex-encoded key for AES-256
}

// Load reads configuration from .env file (if exists) and environment variables
// Environment variables take precedence over .env file values
func Load(envPath string) (*Config, error) {
	// Try to load .env file (optional)
	if envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			if err := godotenv.Load(envPath); err != nil {
				return nil, fmt.Errorf("failed to load .env file: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to check .env file: %w", err)
		}
	}

	cfg := &Config{}

	// Parse environment variables
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse environment variables: %w", err)
	}

	// Parse individual attribute mappings (MAPPING_ATTR_*)
	// This allows setting attributes individually in Kubernetes/Docker environments
	if cfg.Mapping.Attributes == nil {
		cfg.Mapping.Attributes = make(map[string]string)
	}

	// Scan environment for MAPPING_ATTR_* variables
	for _, envVar := range os.Environ() {
		if len(envVar) > 13 && envVar[:13] == "MAPPING_ATTR_" {
			// Split on first '='
			parts := splitOnce(envVar, "=")
			if len(parts) == 2 {
				// Extract attribute name (lowercase the part after MAPPING_ATTR_)
				attrName := parts[0][13:] // Remove "MAPPING_ATTR_" prefix
				attrValue := parts[1]

				// Convert to lowercase for consistency
				// e.g., MAPPING_ATTR_EMAIL -> email, MAPPING_ATTR_USERNAME -> username
				attrNameLower := ""
				for _, c := range attrName {
					if c >= 'A' && c <= 'Z' {
						attrNameLower += string(c + 32) // Convert to lowercase
					} else {
						attrNameLower += string(c)
					}
				}

				cfg.Mapping.Attributes[attrNameLower] = attrValue
			}
		}
	}

	// Handle Port override for Address if Port is set
	if cfg.Server.Port > 0 {
		cfg.Server.Address = fmt.Sprintf(":%d", cfg.Server.Port)
	}

	// Parse and validate encryption key if provided
	if cfg.Storage.EncryptionKey != "" {
		if err := validateEncryptionKey(cfg.Storage.EncryptionKey); err != nil {
			return nil, fmt.Errorf("invalid encryption key: %w", err)
		}
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// splitOnce splits a string on the first occurrence of sep
func splitOnce(s, sep string) []string {
	idx := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			idx = i
			break
		}
	}
	if idx == 0 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+1:]}
}

// Validate checks that all required configuration fields are set
func (c *Config) Validate() error {
	if c.OIDC.IssuerURL == "" {
		return fmt.Errorf("OIDC_ISSUER_URL is required")
	}
	if c.OIDC.ClientID == "" {
		return fmt.Errorf("OIDC_CLIENT_ID is required")
	}
	if c.OIDC.ClientSecret == "" {
		return fmt.Errorf("OIDC_CLIENT_SECRET is required")
	}

	if len(c.OIDC.Scopes) == 0 {
		return fmt.Errorf("OIDC_SCOPES must contain at least one scope")
	}

	// IDP_URL is required
	if c.SAML.IDPURL == "" {
		return fmt.Errorf("IDP_URL is required")
	}

	// Derive OIDC RedirectURL from IDP_URL
	c.OIDC.RedirectURL = c.SAML.IDPURL + "/oidc/callback"

	// Derive SAML EntityID and ACSURL from IDP_URL
	c.SAML.EntityID = c.SAML.IDPURL
	c.SAML.ACSURL = c.SAML.IDPURL + "/saml/acs"

	// If certificate path is provided, private key path must also be provided
	if c.SAML.CertificatePath != "" && c.SAML.PrivateKeyPath == "" {
		return fmt.Errorf("SAML_PRIVATE_KEY_PATH is required when SAML_CERTIFICATE_PATH is set")
	}
	if c.SAML.PrivateKeyPath != "" && c.SAML.CertificatePath == "" {
		return fmt.Errorf("SAML_CERTIFICATE_PATH is required when SAML_PRIVATE_KEY_PATH is set")
	}

	if c.SP.EntityID == "" {
		return fmt.Errorf("SP_ENTITY_ID is required")
	}
	if c.SP.ACSURL == "" {
		return fmt.Errorf("SP_ACS_URL is required")
	}

	if c.Mapping.NameID == "" {
		return fmt.Errorf("MAPPING_NAME_ID is required")
	}

	if c.Session.CookieSecret == "" {
		return fmt.Errorf("SESSION_COOKIE_SECRET is required")
	}

	return nil
}

// validateEncryptionKey validates that the encryption key is a valid 32-byte hex string
func validateEncryptionKey(key string) error {
	// Key should be 64 hex characters (32 bytes)
	if len(key) != 64 {
		return fmt.Errorf("encryption key must be 64 hex characters (32 bytes), got %d", len(key))
	}

	// Validate hex characters
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("encryption key must contain only hexadecimal characters")
		}
	}

	return nil
}
