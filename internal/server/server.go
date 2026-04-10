package server

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"
	"saml-oidc-bridge/internal/oidc"
	"saml-oidc-bridge/internal/saml"
	"time"

	"saml-oidc-bridge/config"
	"saml-oidc-bridge/internal/storage"

	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

// Server represents the HTTP server
type Server struct {
	config     *config.Config
	oidcClient *oidc.Client
	samlIdP    *saml.IdP
	db         *sql.DB
	queries    *storage.Queries
	logger     *zap.Logger
}

// sessionData represents data stored in the session cookie
type sessionData struct {
	RequestID  string
	RelayState string
	State      string
}

// NewServer creates a new HTTP server
func NewServer(cfg *config.Config, logger *zap.Logger) (*Server, error) {
	ctx := context.Background()

	// Initialize OIDC client
	oidcClient, err := oidc.NewClient(
		ctx,
		cfg.OIDC.IssuerURL,
		cfg.OIDC.ClientID,
		cfg.OIDC.ClientSecret,
		cfg.OIDC.RedirectURL,
		cfg.OIDC.Scopes,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC client: %w", err)
	}

	// Create certificate provider based on configuration
	// If certificate paths are provided, use file-path provider, otherwise use self-signed
	var certProvider saml.CertificateProvider
	if cfg.SAML.CertificatePath != "" && cfg.SAML.PrivateKeyPath != "" {
		certProvider, err = saml.NewFilePathCertificateProvider(
			cfg.SAML.CertificatePath,
			cfg.SAML.PrivateKeyPath,
			logger,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create file-path certificate provider: %w", err)
		}
	} else {
		certProvider, err = saml.NewSelfSignedCertificateProvider(logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create self-signed certificate provider: %w", err)
		}
	}

	// Initialize SAML IdP
	samlIdP, err := saml.NewIdP(
		cfg.SAML.EntityID,
		cfg.SAML.ACSURL,
		cfg.SP.EntityID,
		cfg.SP.ACSURL,
		certProvider,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML IdP: %w", err)
	}

	// Initialize database
	db, err := sql.Open("sqlite3", cfg.Storage.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS saml_requests (
		id TEXT PRIMARY KEY,
		relay_state TEXT NOT NULL,
		sp_acs_url TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_saml_requests_expires_at ON saml_requests(expires_at);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	queries := storage.New(db)

	logger.Info("Server initialized",
		zap.String("address", cfg.Server.Address),
		zap.String("database", cfg.Storage.DatabasePath),
	)

	return &Server{
		config:     cfg,
		oidcClient: oidcClient,
		samlIdP:    samlIdP,
		db:         db,
		queries:    queries,
		logger:     logger,
	}, nil
}

// Start starts the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/saml/login", s.handleSAMLLogin)
	mux.HandleFunc("/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/saml/acs", s.handleSAMLACS)
	mux.HandleFunc("/metadata", s.handleMetadata)
	mux.HandleFunc("/healthz", s.handleHealth)

	// Start cleanup goroutine
	go s.cleanupExpiredRequests()

	s.logger.Info("Starting HTTP server", zap.String("address", s.config.Server.Address))

	server := &http.Server{
		Addr:         s.config.Server.Address,
		Handler:      s.securityHeadersMiddleware(s.loggingMiddleware(mux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server.ListenAndServe()
}

// handleSAMLLogin handles the SAML login initiation
func (s *Server) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	s.logger.Info("Received SAML login request", zap.String("remote_addr", r.RemoteAddr))

	// Parse SAML AuthnRequest
	authnRequest, err := s.samlIdP.ParseAuthnRequest(r)
	if err != nil {
		s.logger.Error("Failed to parse AuthnRequest", zap.Error(err))
		http.Error(w, "Invalid SAML request", http.StatusBadRequest)
		return
	}

	// Validate SAML request
	if err := s.validateSAMLRequest(authnRequest); err != nil {
		s.logger.Error("SAML request validation failed", zap.Error(err))
		http.Error(w, "Invalid SAML request", http.StatusBadRequest)
		return
	}

	// Get RelayState
	relayState := s.samlIdP.GetRelayState(r)

	// Validate RelayState
	if err := s.validateRelayState(relayState); err != nil {
		s.logger.Error("RelayState validation failed", zap.Error(err))
		http.Error(w, "Invalid RelayState", http.StatusBadRequest)
		return
	}

	// Generate OAuth state
	state, err := oidc.GenerateState()
	if err != nil {
		s.logger.Error("Failed to generate state", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store request in database
	now := time.Now().Unix()
	expires := time.Now().Add(10 * time.Minute).Unix()

	err = s.queries.CreateSAMLRequest(ctx, storage.CreateSAMLRequestParams{
		ID:         authnRequest.ID,
		RelayState: relayState,
		SpAcsUrl:   s.config.SP.ACSURL,
		CreatedAt:  now,
		ExpiresAt:  expires,
	})
	if err != nil {
		s.logger.Error("Failed to store SAML request", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store state in session cookie
	session := sessionData{
		RequestID:  authnRequest.ID,
		RelayState: relayState,
		State:      state,
	}

	if err := s.setSession(w, session); err != nil {
		s.logger.Error("Failed to set session", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Redirect to OIDC provider
	authURL := s.oidcClient.GetAuthorizationURL(state)
	s.logger.Info("Redirecting to OIDC provider",
		zap.String("request_id", authnRequest.ID),
		zap.String("state", state),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback handles the OAuth2 callback
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	s.logger.Info("Received OIDC callback", zap.String("remote_addr", r.RemoteAddr))

	// Get session
	session, err := s.getSession(r)
	if err != nil {
		s.logger.Error("Failed to get session", zap.Error(err))
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	// Verify state
	state := r.URL.Query().Get("state")

	// Validate state format
	if err := s.validateOAuthState(state); err != nil {
		s.logger.Error("OAuth state validation failed", zap.Error(err))
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	if state != session.State {
		s.logger.Error("State mismatch",
			zap.String("expected", session.State),
			zap.String("received", state),
		)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		s.logger.Error("Missing authorization code")
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	userClaims, err := s.oidcClient.HandleCallback(ctx, code)
	if err != nil {
		s.logger.Error("Failed to handle callback", zap.Error(err))
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Get stored SAML request
	samlRequest, err := s.queries.GetSAMLRequest(ctx, session.RequestID)
	if err != nil {
		s.logger.Error("Failed to get SAML request", zap.Error(err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Map OIDC claims to SAML attributes
	nameID := userClaims.GetClaimValue(s.config.Mapping.NameID)
	if nameID == "" {
		s.logger.Error("Failed to get NameID from claims",
			zap.String("name_id_claim", s.config.Mapping.NameID),
		)
		http.Error(w, "Missing required claim", http.StatusInternalServerError)
		return
	}

	attributes := make(map[string]string)
	for samlAttr, oidcClaim := range s.config.Mapping.Attributes {
		value := userClaims.GetClaimValue(oidcClaim)
		if value != "" {
			attributes[samlAttr] = value
		}
	}

	// Create SAML response
	samlResponse, err := s.samlIdP.CreateResponse(session.RequestID, nameID, attributes)
	if err != nil {
		s.logger.Error("Failed to create SAML response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Sign response
	if err := s.samlIdP.SignResponse(samlResponse); err != nil {
		s.logger.Error("Failed to sign SAML response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Marshal response to XML
	responseXML, err := xml.Marshal(samlResponse)
	if err != nil {
		s.logger.Error("Failed to marshal SAML response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Base64 encode
	responseEncoded := base64.StdEncoding.EncodeToString(responseXML)

	// Delete used request
	if err := s.queries.DeleteSAMLRequest(ctx, session.RequestID); err != nil {
		s.logger.Warn("Failed to delete SAML request", zap.Error(err))
	}

	// Clear session
	s.clearSession(w)

	s.logger.Info("Sending SAML response to SP",
		zap.String("sp_acs_url", samlRequest.SpAcsUrl),
		zap.String("name_id", nameID),
	)

	// Render auto-submit form
	s.renderSAMLResponse(w, samlRequest.SpAcsUrl, responseEncoded, samlRequest.RelayState)
}

// handleSAMLACS handles POST to ACS (not typically used in this flow)
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	s.logger.Warn("Received unexpected POST to /saml/acs")
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// handleMetadata returns SAML IdP metadata
func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Serving SAML metadata")

	metadata, err := s.samlIdP.GetMetadata()
	if err != nil {
		s.logger.Error("Failed to generate metadata", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	metadataXML, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		s.logger.Error("Failed to marshal metadata", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(xml.Header))
	w.Write(metadataXML)
}

// handleHealth returns health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

// setSession stores session data in a cookie
func (s *Server) setSession(w http.ResponseWriter, data sessionData) error {
	// JSON encode session data
	sessionJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	cookie := &http.Cookie{
		Name:     s.config.Session.CookieName,
		Value:    base64.StdEncoding.EncodeToString(sessionJSON),
		Path:     "/",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
		Secure:   s.config.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)
	return nil
}

// getSession retrieves session data from a cookie
func (s *Server) getSession(r *http.Request) (*sessionData, error) {
	cookie, err := r.Cookie(s.config.Session.CookieName)
	if err != nil {
		return nil, fmt.Errorf("session cookie not found: %w", err)
	}

	sessionJSON, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode session: %w", err)
	}

	var data sessionData
	if err := json.Unmarshal(sessionJSON, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &data, nil
}

// clearSession removes the session cookie
func (s *Server) clearSession(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     s.config.Session.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}

// renderSAMLResponse renders an auto-submit form to POST the SAML response
func (s *Server) renderSAMLResponse(w http.ResponseWriter, acsURL, samlResponse, relayState string) {
	tmpl := template.Must(template.New("saml").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>SAML Response</title>
</head>
<body onload="document.forms[0].submit()">
    <form method="post" action="{{.ACSURL}}">
        <input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />
        {{if .RelayState}}
        <input type="hidden" name="RelayState" value="{{.RelayState}}" />
        {{end}}
        <noscript>
            <p>JavaScript is disabled. Please click the button below to continue.</p>
            <input type="submit" value="Continue" />
        </noscript>
    </form>
</body>
</html>
`))

	data := struct {
		ACSURL       string
		SAMLResponse string
		RelayState   string
	}{
		ACSURL:       acsURL,
		SAMLResponse: samlResponse,
		RelayState:   relayState,
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		s.logger.Error("Failed to render SAML response", zap.Error(err))
	}
}

// cleanupExpiredRequests periodically removes expired SAML requests
func (s *Server) cleanupExpiredRequests() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()
		now := time.Now().Unix()

		if err := s.queries.DeleteExpiredRequests(ctx, now); err != nil {
			s.logger.Error("Failed to cleanup expired requests", zap.Error(err))
		} else {
			s.logger.Debug("Cleaned up expired requests")
		}
	}
}

// Close closes the server resources
func (s *Server) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
