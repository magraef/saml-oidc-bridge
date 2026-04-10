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
	RedirectURL  string   `env:"OIDC_REDIRECT_URL"`
	Scopes       []string `env:"OIDC_SCOPES" envSeparator:"," envDefault:"openid,profile,email"`
}

// SAMLConfig contains SAML IdP settings for this proxy
type SAMLConfig struct {
	EntityID        string `env:"SAML_ENTITY_ID"`
	ACSURL          string `env:"SAML_ACS_URL"`
	CertificatePath string `env:"SAML_CERTIFICATE_PATH"`
	PrivateKeyPath  string `env:"SAML_PRIVATE_KEY_PATH"`
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
	DatabasePath string `env:"STORAGE_DATABASE_PATH" envDefault:"./saml-oidc-bridge.db"`
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

	// Handle Port override for Address if Port is set
	if cfg.Server.Port > 0 {
		cfg.Server.Address = fmt.Sprintf(":%d", cfg.Server.Port)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
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
	if c.OIDC.RedirectURL == "" {
		return fmt.Errorf("OIDC_REDIRECT_URL is required")
	}
	if len(c.OIDC.Scopes) == 0 {
		return fmt.Errorf("OIDC_SCOPES must contain at least one scope")
	}

	if c.SAML.EntityID == "" {
		return fmt.Errorf("SAML_ENTITY_ID is required")
	}
	if c.SAML.ACSURL == "" {
		return fmt.Errorf("SAML_ACS_URL is required")
	}

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
