package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	// Create a temporary .env file
	tmpfile, err := os.CreateTemp("", "test-*.env")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	envContent := `OIDC_ISSUER_URL=https://accounts.google.com
OIDC_CLIENT_ID=test-client-id
OIDC_CLIENT_SECRET=test-secret
OIDC_SCOPES=openid,profile,email
IDP_URL=https://proxy.example.com
SAML_CERTIFICATE_PATH=/certs/tls.crt
SAML_PRIVATE_KEY_PATH=/certs/tls.key
SP_ENTITY_ID=https://app.example.com/metadata
SP_ACS_URL=https://app.example.com/saml/acs
MAPPING_NAME_ID=email
SESSION_COOKIE_SECRET=test-secret-key
SESSION_COOKIE_SECURE=true
SERVER_ADDRESS=:8080
DEBUG=false
STORAGE_DATABASE_PATH=./test.db
`

	if _, err := tmpfile.Write([]byte(envContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Clean up any existing env vars that might interfere
	os.Unsetenv("STORAGE_DATABASE_PATH")

	cfg, err := Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify OIDC config
	if cfg.OIDC.IssuerURL != "https://accounts.google.com" {
		t.Errorf("Expected issuer_url to be https://accounts.google.com, got %s", cfg.OIDC.IssuerURL)
	}
	if cfg.OIDC.ClientID != "test-client-id" {
		t.Errorf("Expected client_id to be test-client-id, got %s", cfg.OIDC.ClientID)
	}
	if len(cfg.OIDC.Scopes) != 3 {
		t.Errorf("Expected 3 scopes, got %d", len(cfg.OIDC.Scopes))
	}
	if cfg.OIDC.RedirectURL != "https://proxy.example.com/oidc/callback" {
		t.Errorf("Expected redirect_url derived from IDP_URL, got %s", cfg.OIDC.RedirectURL)
	}

	// Verify SAML config (derived from IDP_URL)
	if cfg.SAML.EntityID != "https://proxy.example.com" {
		t.Errorf("Expected entity_id to be https://proxy.example.com, got %s", cfg.SAML.EntityID)
	}
	if cfg.SAML.ACSURL != "https://proxy.example.com/saml/acs" {
		t.Errorf("Expected acs_url to be https://proxy.example.com/saml/acs, got %s", cfg.SAML.ACSURL)
	}

	// Verify mapping
	if cfg.Mapping.NameID != "email" {
		t.Errorf("Expected name_id to be email, got %s", cfg.Mapping.NameID)
	}

	// Verify server config
	if cfg.Server.Debug != false {
		t.Errorf("Expected debug to be false, got %v", cfg.Server.Debug)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with IDP_URL",
			config: Config{
				OIDC: OIDCConfig{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "test-client",
					ClientSecret: "test-secret",
					Scopes:       []string{"openid"},
				},
				SAML: SAMLConfig{
					IDPURL:          "https://proxy.example.com",
					CertificatePath: "/certs/tls.crt",
					PrivateKeyPath:  "/certs/tls.key",
				},
				SP: SPConfig{
					EntityID: "https://app.example.com",
					ACSURL:   "https://app.example.com/saml/acs",
				},
				Mapping: MappingConfig{
					NameID: "email",
				},
				Session: SessionConfig{
					CookieSecret: "secret",
				},
			},
			wantErr: false,
		},
		{
			name: "missing OIDC issuer",
			config: Config{
				OIDC: OIDCConfig{
					ClientID:     "test-client",
					ClientSecret: "test-secret",
					RedirectURL:  "https://proxy.example.com/callback",
					Scopes:       []string{"openid"},
				},
			},
			wantErr: true,
			errMsg:  "OIDC_ISSUER_URL is required",
		},
		{
			name: "missing IDP_URL",
			config: Config{
				OIDC: OIDCConfig{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "test-client",
					ClientSecret: "test-secret",
					RedirectURL:  "https://proxy.example.com/callback",
					Scopes:       []string{"openid"},
				},
				SAML: SAMLConfig{
					CertificatePath: "/certs/tls.crt",
					PrivateKeyPath:  "/certs/tls.key",
				},
				SP: SPConfig{
					EntityID: "https://app.example.com",
					ACSURL:   "https://app.example.com/saml/acs",
				},
				Mapping: MappingConfig{
					NameID: "email",
				},
				Session: SessionConfig{
					CookieSecret: "secret",
				},
			},
			wantErr: true,
			errMsg:  "IDP_URL is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("Validate() error = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Set environment variables
	os.Setenv("OIDC_ISSUER_URL", "https://test.example.com")
	os.Setenv("OIDC_CLIENT_ID", "env-client-id")
	os.Setenv("OIDC_CLIENT_SECRET", "env-secret")
	os.Setenv("OIDC_SCOPES", "openid,profile,email")
	os.Setenv("IDP_URL", "https://env-proxy.example.com")
	os.Setenv("SAML_CERTIFICATE_PATH", "/tmp/cert.pem")
	os.Setenv("SAML_PRIVATE_KEY_PATH", "/tmp/key.pem")
	os.Setenv("SP_ENTITY_ID", "https://sp.example.com")
	os.Setenv("SP_ACS_URL", "https://sp.example.com/acs")
	os.Setenv("MAPPING_NAME_ID", "email")
	os.Setenv("SESSION_COOKIE_SECRET", "test-secret")
	os.Setenv("SESSION_COOKIE_SECURE", "false")
	os.Setenv("DEBUG", "true")
	os.Setenv("PORT", "9090")
	defer func() {
		os.Unsetenv("OIDC_ISSUER_URL")
		os.Unsetenv("OIDC_CLIENT_ID")
		os.Unsetenv("OIDC_CLIENT_SECRET")
		os.Unsetenv("OIDC_SCOPES")
		os.Unsetenv("IDP_URL")
		os.Unsetenv("SAML_CERTIFICATE_PATH")
		os.Unsetenv("SAML_PRIVATE_KEY_PATH")
		os.Unsetenv("SP_ENTITY_ID")
		os.Unsetenv("SP_ACS_URL")
		os.Unsetenv("MAPPING_NAME_ID")
		os.Unsetenv("SESSION_COOKIE_SECRET")
		os.Unsetenv("SESSION_COOKIE_SECURE")
		os.Unsetenv("DEBUG")
		os.Unsetenv("PORT")
	}()

	// Load config with non-existent file (should use env vars only)
	cfg, err := Load("/nonexistent/.env")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify environment variables are loaded
	if cfg.OIDC.IssuerURL != "https://test.example.com" {
		t.Errorf("Expected issuer_url from env, got %s", cfg.OIDC.IssuerURL)
	}
	if cfg.OIDC.ClientID != "env-client-id" {
		t.Errorf("Expected client_id from env, got %s", cfg.OIDC.ClientID)
	}
	if len(cfg.OIDC.Scopes) != 3 {
		t.Errorf("Expected 3 scopes from env, got %d", len(cfg.OIDC.Scopes))
	}
	if cfg.OIDC.RedirectURL != "https://env-proxy.example.com/oidc/callback" {
		t.Errorf("Expected redirect_url derived from IDP_URL, got %s", cfg.OIDC.RedirectURL)
	}
	if cfg.SAML.EntityID != "https://env-proxy.example.com" {
		t.Errorf("Expected entity_id derived from IDP_URL, got %s", cfg.SAML.EntityID)
	}
	if cfg.SAML.ACSURL != "https://env-proxy.example.com/saml/acs" {
		t.Errorf("Expected acs_url derived from IDP_URL, got %s", cfg.SAML.ACSURL)
	}
	if cfg.Session.CookieSecure != false {
		t.Errorf("Expected cookie_secure to be false from env")
	}
	if cfg.Server.Debug != true {
		t.Errorf("Expected debug to be true from env")
	}
	if cfg.Server.Address != ":9090" {
		t.Errorf("Expected address to be :9090 from PORT env, got %s", cfg.Server.Address)
	}
}

func TestLoadDefaults(t *testing.T) {
	// Clean up any existing env vars from previous tests
	os.Unsetenv("STORAGE_DATABASE_PATH")

	// Set only required environment variables
	os.Setenv("OIDC_ISSUER_URL", "https://test.example.com")
	os.Setenv("OIDC_CLIENT_ID", "test-client")
	os.Setenv("OIDC_CLIENT_SECRET", "test-secret")
	os.Setenv("IDP_URL", "https://saml.example.com")
	os.Setenv("SAML_CERTIFICATE_PATH", "/tmp/cert.pem")
	os.Setenv("SAML_PRIVATE_KEY_PATH", "/tmp/key.pem")
	os.Setenv("SP_ENTITY_ID", "https://sp.example.com")
	os.Setenv("SP_ACS_URL", "https://sp.example.com/acs")
	os.Setenv("MAPPING_NAME_ID", "email")
	os.Setenv("SESSION_COOKIE_SECRET", "test-secret")
	defer func() {
		os.Unsetenv("OIDC_ISSUER_URL")
		os.Unsetenv("OIDC_CLIENT_ID")
		os.Unsetenv("OIDC_CLIENT_SECRET")
		os.Unsetenv("IDP_URL")
		os.Unsetenv("SAML_CERTIFICATE_PATH")
		os.Unsetenv("SAML_PRIVATE_KEY_PATH")
		os.Unsetenv("SP_ENTITY_ID")
		os.Unsetenv("SP_ACS_URL")
		os.Unsetenv("MAPPING_NAME_ID")
		os.Unsetenv("SESSION_COOKIE_SECRET")
	}()

	cfg, err := Load("/nonexistent/.env")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify defaults are applied
	if len(cfg.OIDC.Scopes) != 3 || cfg.OIDC.Scopes[0] != "openid" {
		t.Errorf("Expected default scopes [openid, profile, email], got %v", cfg.OIDC.Scopes)
	}
	if cfg.Session.CookieName != "saml-oidc-bridge-session" {
		t.Errorf("Expected default cookie_name, got %s", cfg.Session.CookieName)
	}
	if cfg.Session.CookieSecure != false {
		t.Errorf("Expected default cookie_secure to be false")
	}
	if cfg.Server.Address != ":8080" {
		t.Errorf("Expected default address :8080, got %s", cfg.Server.Address)
	}
	if cfg.Server.Debug != false {
		t.Errorf("Expected default debug to be false")
	}
	if cfg.Storage.DatabasePath != "./saml-oidc-bridge.db" {
		t.Errorf("Expected default database_path, got %s", cfg.Storage.DatabasePath)
	}
}

func TestEnvFileOverride(t *testing.T) {
	// Create a temporary .env file
	tmpfile, err := os.CreateTemp("", "test-*.env")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	envContent := `OIDC_ISSUER_URL=https://file.example.com
OIDC_CLIENT_ID=file-client-id
OIDC_CLIENT_SECRET=file-secret
IDP_URL=https://file-saml.example.com
SAML_CERTIFICATE_PATH=/tmp/cert.pem
SAML_PRIVATE_KEY_PATH=/tmp/key.pem
SP_ENTITY_ID=https://file-sp.example.com
SP_ACS_URL=https://file-sp.example.com/acs
MAPPING_NAME_ID=email
SESSION_COOKIE_SECRET=file-secret
DEBUG=false
`

	if _, err := tmpfile.Write([]byte(envContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Set environment variable that should override .env file
	os.Setenv("OIDC_CLIENT_ID", "env-override-client-id")
	os.Setenv("DEBUG", "true")
	defer func() {
		os.Unsetenv("OIDC_CLIENT_ID")
		os.Unsetenv("DEBUG")
	}()

	cfg, err := Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify env var overrides .env file
	if cfg.OIDC.ClientID != "env-override-client-id" {
		t.Errorf("Expected client_id to be overridden by env var, got %s", cfg.OIDC.ClientID)
	}
	if cfg.Server.Debug != true {
		t.Errorf("Expected debug to be overridden by env var to true")
	}

	// Verify .env file values are used when no env var override
	if cfg.OIDC.IssuerURL != "https://file.example.com" {
		t.Errorf("Expected issuer_url from .env file, got %s", cfg.OIDC.IssuerURL)
	}
}
