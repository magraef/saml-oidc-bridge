package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"saml-oidc-bridge/config"
	"saml-oidc-bridge/internal/oidc"
	"saml-oidc-bridge/internal/saml"
	"saml-oidc-bridge/internal/storage"

	"go.uber.org/zap"
)

// Server represents the HTTP server
type Server struct {
	oidcAuth         OIDCAuthenticator
	samlParser       SAMLRequestParser
	samlResponder    SAMLResponseCreator
	samlMetadata     SAMLMetadataProvider
	samlRequestStore SAMLRequestStore
	requestCleaner   ExpiredRequestCleaner
	claimsMapper     ClaimsMapper
	store            *storage.Store
	logger           *zap.Logger
	cookieName       string
	cookieSecure     bool
	spEntityID       string
	spACSURL         string
	maxRelayState    int
}

// sessionData represents data stored in the session cookie
type sessionData struct {
	RequestID  string
	RelayState string
	State      string
}

// NewServer creates a new HTTP server with concrete implementations
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

	// Initialize storage with migrations
	store, err := storage.NewStore(cfg.Storage.DatabasePath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Create claims mapper
	claimsMapper := NewConfigClaimsMapper(&cfg.Mapping)

	logger.Info("Server initialized",
		zap.String("address", cfg.Server.Address),
		zap.String("database", cfg.Storage.DatabasePath),
	)

	return &Server{
		oidcAuth:         oidcClient,
		samlParser:       samlIdP,
		samlResponder:    samlIdP,
		samlMetadata:     samlIdP,
		samlRequestStore: store,
		requestCleaner:   store,
		claimsMapper:     claimsMapper,
		store:            store,
		logger:           logger,
		cookieName:       cfg.Session.CookieName,
		cookieSecure:     cfg.Session.CookieSecure,
		spEntityID:       cfg.SP.EntityID,
		spACSURL:         cfg.SP.ACSURL,
		maxRelayState:    80, // Default SAML spec recommendation
	}, nil
}

// NewServerWithDependencies creates a new HTTP server with injected dependencies (for testing)
func NewServerWithDependencies(
	oidcAuth OIDCAuthenticator,
	samlParser SAMLRequestParser,
	samlResponder SAMLResponseCreator,
	samlMetadata SAMLMetadataProvider,
	samlRequestStore SAMLRequestStore,
	requestCleaner ExpiredRequestCleaner,
	claimsMapper ClaimsMapper,
	store *storage.Store,
	logger *zap.Logger,
	cookieName string,
	cookieSecure bool,
	spEntityID string,
	spACSURL string,
	maxRelayState int,
) *Server {
	return &Server{
		oidcAuth:         oidcAuth,
		samlParser:       samlParser,
		samlResponder:    samlResponder,
		samlMetadata:     samlMetadata,
		samlRequestStore: samlRequestStore,
		requestCleaner:   requestCleaner,
		claimsMapper:     claimsMapper,
		store:            store,
		logger:           logger,
		cookieName:       cookieName,
		cookieSecure:     cookieSecure,
		spEntityID:       spEntityID,
		spACSURL:         spACSURL,
		maxRelayState:    maxRelayState,
	}
}

// Start starts the HTTP server
func (s *Server) Start(address string) error {
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/saml/login", s.handleSAMLLogin)
	mux.HandleFunc("/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/saml/acs", s.handleSAMLACS)
	mux.HandleFunc("/metadata", s.handleMetadata)
	mux.HandleFunc("/healthz", s.handleHealth)

	// Start cleanup goroutine
	go s.cleanupExpiredRequests()

	s.logger.Info("Starting HTTP server", zap.String("address", address))

	server := &http.Server{
		Addr:         address,
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
	authnRequest, err := s.samlParser.ParseAuthnRequest(r)
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
	relayState := s.samlParser.GetRelayState(r)

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

	// Store request in session store
	// Note: SP ACS URL is retrieved from the parsed SAML request's AssertionConsumerServiceURL
	// or we need to pass it as a parameter. For now, using a placeholder approach.
	spACSURL := authnRequest.AssertionConsumerServiceURL
	if spACSURL == "" {
		// Fallback: this should be validated earlier
		s.logger.Error("Missing ACS URL in SAML request")
		http.Error(w, "Invalid SAML request", http.StatusBadRequest)
		return
	}

	err = s.samlRequestStore.StoreSAMLRequest(ctx, authnRequest.ID, relayState, spACSURL)
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
	authURL := s.oidcAuth.GetAuthorizationURL(state)
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
	userClaims, err := s.oidcAuth.ExchangeCodeForToken(ctx, code)
	if err != nil {
		s.logger.Error("Failed to handle callback", zap.Error(err))
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Get stored SAML request
	relayState, spACSURL, err := s.samlRequestStore.GetSAMLRequestData(ctx, session.RequestID)
	if err != nil {
		s.logger.Error("Failed to get SAML request", zap.Error(err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Map OIDC claims to SAML attributes using the claims mapper
	nameID := s.claimsMapper.GetNameID(userClaims)
	if nameID == "" {
		s.logger.Error("Failed to get NameID from claims")
		http.Error(w, "Missing required claim", http.StatusInternalServerError)
		return
	}

	attributes := s.claimsMapper.MapAttributes(userClaims)

	// Create and sign SAML response (returns signed XML bytes)
	responseXML, err := s.samlResponder.CreateResponse(session.RequestID, nameID, attributes)
	if err != nil {
		s.logger.Error("Failed to create SAML response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Base64 encode
	responseEncoded := base64.StdEncoding.EncodeToString(responseXML)

	// Delete used request
	if err := s.samlRequestStore.DeleteSAMLRequest(ctx, session.RequestID); err != nil {
		s.logger.Warn("Failed to delete SAML request", zap.Error(err))
	}

	// Clear session
	s.clearSession(w)

	s.logger.Info("Sending SAML response to SP",
		zap.String("sp_acs_url", spACSURL),
		zap.String("name_id", nameID),
	)

	// Render auto-submit form
	s.renderSAMLResponse(w, spACSURL, responseEncoded, relayState)
}

// handleSAMLACS handles POST to ACS (not typically used in this flow)
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	s.logger.Warn("Received unexpected POST to /saml/acs")
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// handleMetadata returns SAML IdP metadata
func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Serving SAML metadata")

	metadata, err := s.samlMetadata.GetMetadata()
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
		Name:     s.cookieName,
		Value:    base64.StdEncoding.EncodeToString(sessionJSON),
		Path:     "/",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)
	return nil
}

// getSession retrieves session data from a cookie
func (s *Server) getSession(r *http.Request) (*sessionData, error) {
	cookie, err := r.Cookie(s.cookieName)
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
		Name:     s.cookieName,
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

		if err := s.requestCleaner.CleanupExpired(ctx, now); err != nil {
			s.logger.Error("Failed to cleanup expired requests", zap.Error(err))
		} else {
			s.logger.Debug("Cleaned up expired requests")
		}
	}
}

// Close closes the server resources
func (s *Server) Close() error {
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}
