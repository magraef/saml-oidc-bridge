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

	"github.com/crewjam/saml"
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
	mux.HandleFunc("/saml/logout", s.handleSAMLLogout)
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

	// Store session for logout support (if store is available)
	if s.store != nil {
		sessionIndex := fmt.Sprintf("session-%d", time.Now().UnixNano())
		now := time.Now().Unix()
		expires := time.Now().Add(24 * time.Hour).Unix()

		// Store session with ID token for OIDC logout
		err = s.store.CreateSession(ctx, storage.CreateSessionParams{
			SessionIndex: sessionIndex,
			NameID:       nameID,
			IDToken:      userClaims.IDToken,
			SpEntityID:   s.spEntityID,
			CreatedAt:    now,
			ExpiresAt:    expires,
		})
		if err != nil {
			s.logger.Warn("Failed to store session", zap.Error(err))
			// Continue anyway - logout will still work without session
		} else {
			s.logger.Debug("Created session for logout",
				zap.String("session_index", sessionIndex),
				zap.String("name_id", nameID),
			)
		}
	}

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

// handleSAMLLogout handles SAML logout requests
func (s *Server) handleSAMLLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	s.logger.Info("Received SAML logout request", zap.String("remote_addr", r.RemoteAddr))

	// Parse SAML LogoutRequest
	logoutRequest, err := s.samlResponder.(interface {
		ParseLogoutRequest(*http.Request) (*saml.LogoutRequest, error)
	}).ParseLogoutRequest(r)
	if err != nil {
		s.logger.Error("Failed to parse LogoutRequest", zap.Error(err))
		http.Error(w, "Invalid SAML logout request", http.StatusBadRequest)
		return
	}

	s.logger.Debug("Parsed SAML LogoutRequest",
		zap.String("request_id", logoutRequest.ID),
		zap.String("issuer", logoutRequest.Issuer.Value),
	)

	// Validate logout request
	if err := s.validateLogoutRequest(logoutRequest); err != nil {
		s.logger.Error("Logout request validation failed", zap.Error(err))
		s.sendLogoutError(w, logoutRequest.ID, "urn:oasis:names:tc:SAML:2.0:status:Requester")
		return
	}

	// Get session index from logout request
	var sessionIndex string
	if logoutRequest.SessionIndex != nil {
		sessionIndex = logoutRequest.SessionIndex.Value
	}

	s.logger.Debug("Processing logout for session",
		zap.String("session_index", sessionIndex),
	)

	// Get session from database
	session, err := s.store.GetSession(ctx, sessionIndex)
	if err != nil {
		s.logger.Warn("Session not found",
			zap.String("session_index", sessionIndex),
			zap.Error(err),
		)
		// Continue with logout even if session not found
	}

	// Perform OIDC logout if session exists and has ID token
	if session.IDToken != "" {
		logoutURL, err := s.oidcAuth.(interface {
			GetLogoutURL(string, string) (string, error)
		}).GetLogoutURL(session.IDToken, "")
		if err != nil {
			s.logger.Warn("Failed to get OIDC logout URL", zap.Error(err))
		} else {
			// Call OIDC logout endpoint asynchronously
			go func() {
				s.logger.Debug("Calling OIDC logout endpoint", zap.String("url", logoutURL))
				resp, err := http.Get(logoutURL)
				if err != nil {
					s.logger.Error("OIDC logout failed", zap.Error(err))
					return
				}
				defer resp.Body.Close()
				s.logger.Info("OIDC logout completed", zap.Int("status", resp.StatusCode))
			}()
		}
	}

	// Delete session from database
	if sessionIndex != "" {
		if err := s.store.DeleteSession(ctx, sessionIndex); err != nil {
			s.logger.Warn("Failed to delete session", zap.Error(err))
		} else {
			s.logger.Debug("Deleted session from store", zap.String("session_index", sessionIndex))
		}
	}

	// Create successful logout response
	logoutResponseXML, err := s.samlResponder.(interface {
		CreateLogoutResponse(string, string) ([]byte, error)
	}).CreateLogoutResponse(logoutRequest.ID, "urn:oasis:names:tc:SAML:2.0:status:Success")
	if err != nil {
		s.logger.Error("Failed to create logout response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Base64 encode
	responseEncoded := base64.StdEncoding.EncodeToString(logoutResponseXML)

	// Get RelayState
	relayState := s.samlParser.GetRelayState(r)

	s.logger.Info("Sending SAML logout response to SP",
		zap.String("sp_acs_url", s.spACSURL),
		zap.String("request_id", logoutRequest.ID),
	)

	// Render auto-submit form
	s.renderSAMLLogoutResponse(w, s.spACSURL, responseEncoded, relayState)
}

// validateLogoutRequest validates a SAML logout request
func (s *Server) validateLogoutRequest(req *saml.LogoutRequest) error {
	// Validate issuer
	if req.Issuer.Value != s.spEntityID {
		return fmt.Errorf("invalid issuer: %s", req.Issuer.Value)
	}

	// Validate timestamp (allow 5 minute clock skew)
	now := time.Now()
	if req.IssueInstant.Before(now.Add(-5 * time.Minute)) {
		return fmt.Errorf("logout request too old")
	}
	if req.IssueInstant.After(now.Add(5 * time.Minute)) {
		return fmt.Errorf("logout request from future")
	}

	return nil
}

// sendLogoutError sends a SAML logout error response
func (s *Server) sendLogoutError(w http.ResponseWriter, requestID, statusCode string) {
	logoutResponseXML, err := s.samlResponder.(interface {
		CreateLogoutResponse(string, string) ([]byte, error)
	}).CreateLogoutResponse(requestID, statusCode)
	if err != nil {
		s.logger.Error("Failed to create error logout response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	responseEncoded := base64.StdEncoding.EncodeToString(logoutResponseXML)
	relayState := ""

	s.renderSAMLLogoutResponse(w, s.spACSURL, responseEncoded, relayState)
}

// renderSAMLLogoutResponse renders an auto-submit form for logout response
func (s *Server) renderSAMLLogoutResponse(w http.ResponseWriter, acsURL, samlResponse, relayState string) {
	tmpl := template.Must(template.New("logout").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>SAML Logout</title>
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
		s.logger.Error("Failed to render logout response", zap.Error(err))
	}
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
