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

	"saml-oidc-bridge/internal/oidc"
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
	claimsMapper     ClaimsMapper
	store            *storage.Store
	logger           *zap.Logger
	cookieName       string
	cookieSecure     bool
	spEntityID       string
	spACSURL         string
	maxRelayState    int
	cancel           context.CancelFunc
}

// sessionData represents data stored in the session cookie
type sessionData struct {
	RequestID  string
	RelayState string
	State      string
}

// NewServer creates a new HTTP server with injected dependencies
// Follows the pattern: Accept Interfaces, Return Instances
// It accepts a context that will be used to manage the server lifecycle.
func NewServer(
	ctx context.Context,
	oidcAuth OIDCAuthenticator,
	samlParser SAMLRequestParser,
	samlResponder SAMLResponseCreator,
	samlMetadata SAMLMetadataProvider,
	samlRequestStore SAMLRequestStore,
	claimsMapper ClaimsMapper,
	store *storage.Store,
	logger *zap.Logger,
	cookieName string,
	cookieSecure bool,
	spEntityID string,
	spACSURL string,
	maxRelayState int,
) *Server {
	_, cancel := context.WithCancel(ctx)

	return &Server{
		oidcAuth:         oidcAuth,
		samlParser:       samlParser,
		samlResponder:    samlResponder,
		samlMetadata:     samlMetadata,
		samlRequestStore: samlRequestStore,
		claimsMapper:     claimsMapper,
		store:            store,
		logger:           logger,
		cookieName:       cookieName,
		cookieSecure:     cookieSecure,
		spEntityID:       spEntityID,
		spACSURL:         spACSURL,
		maxRelayState:    maxRelayState,
		cancel:           cancel,
	}
}

// Handler returns the HTTP handler for the server
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/saml/login", s.handleSAMLLogin)
	mux.HandleFunc("/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/saml/acs", s.handleSAMLACS)
	mux.HandleFunc("/metadata", s.handleMetadata)
	mux.HandleFunc("/healthz", s.handleHealth)

	return s.securityHeadersMiddleware(s.loggingMiddleware(mux))
}

// Start starts the HTTP server and blocks until shutdown
func (s *Server) Start(ctx context.Context, address string) error {
	server := &http.Server{
		Addr:         address,
		Handler:      s.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		s.logger.Info("HTTP server listening", zap.String("address", address))
		errChan <- server.ListenAndServe()
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Info("Shutting down HTTP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("Server shutdown error", zap.Error(err))
			return err
		}
		s.logger.Info("HTTP server stopped")
		return nil
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
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

	// Log detailed SAML request information
	s.logger.Debug("Parsed SAML AuthnRequest",
		zap.String("request_id", authnRequest.ID),
		zap.String("issuer", authnRequest.Issuer.Value),
		zap.String("acs_url", authnRequest.AssertionConsumerServiceURL),
		zap.String("destination", authnRequest.Destination),
		zap.Time("issue_instant", authnRequest.IssueInstant),
		zap.String("protocol_binding", authnRequest.ProtocolBinding),
	)

	// Validate SAML request
	if err := s.validateSAMLRequest(authnRequest); err != nil {
		s.logger.Error("SAML request validation failed", zap.Error(err))
		http.Error(w, "Invalid SAML request", http.StatusBadRequest)
		return
	}

	// Get RelayState
	relayState := s.samlParser.GetRelayState(r)

	if relayState != "" {
		s.logger.Debug("SAML request includes RelayState",
			zap.String("relay_state", relayState),
			zap.Int("relay_state_length", len(relayState)),
		)
	}

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

	s.logger.Debug("Created session cookie",
		zap.String("request_id", authnRequest.ID),
		zap.String("state", state),
		zap.Bool("has_relay_state", relayState != ""),
	)

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

	s.logger.Debug("Retrieved session from cookie",
		zap.String("request_id", session.RequestID),
		zap.String("state", session.State),
		zap.Bool("has_relay_state", session.RelayState != ""),
	)

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
	s.logger.Debug("Exchanging authorization code for tokens",
		zap.String("request_id", session.RequestID),
	)

	userClaims, err := s.oidcAuth.ExchangeCodeForToken(ctx, code)
	if err != nil {
		s.logger.Error("Failed to handle callback", zap.Error(err))
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Log extracted OIDC claims (without sensitive data)
	s.logger.Debug("Successfully extracted OIDC user claims",
		zap.String("subject", userClaims.Subject),
		zap.String("email", userClaims.Email),
		zap.Bool("email_verified", userClaims.EmailVerified),
		zap.String("preferred_username", userClaims.PreferredUsername),
		zap.Int("total_claims_count", len(userClaims.Claims)),
	)

	// Get stored SAML request
	relayState, spACSURL, err := s.samlRequestStore.GetSAMLRequestData(ctx, session.RequestID)
	if err != nil {
		s.logger.Error("Failed to get SAML request", zap.Error(err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	s.logger.Debug("Retrieved stored SAML request data",
		zap.String("request_id", session.RequestID),
		zap.String("sp_acs_url", spACSURL),
		zap.Bool("has_relay_state", relayState != ""),
	)

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
	} else {
		s.logger.Debug("Deleted SAML request from store",
			zap.String("request_id", session.RequestID),
		)
	}

	// Clear session
	s.clearSession(w)
	s.logger.Debug("Cleared session cookie",
		zap.String("request_id", session.RequestID),
	)

	s.logger.Info("Sending SAML response to SP",
		zap.String("sp_acs_url", spACSURL),
		zap.String("name_id", nameID),
		zap.Int("attributes_count", len(attributes)),
		zap.String("request_id", session.RequestID),
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

// Close closes the server resources
func (s *Server) Close() error {
	s.logger.Debug("Shutting down server")

	// Cancel server context
	if s.cancel != nil {
		s.cancel()
	}

	// Close store (which will stop cleanup goroutine)
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}
