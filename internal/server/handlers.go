package server

import "net/http"

// Public handler methods for testing

// HandleSAMLLogin exposes the SAML login handler for testing
func (s *Server) HandleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	s.handleSAMLLogin(w, r)
}

// HandleOIDCCallback exposes the OIDC callback handler for testing
func (s *Server) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	s.handleOIDCCallback(w, r)
}

// HandleSAMLACS exposes the SAML ACS handler for testing
func (s *Server) HandleSAMLACS(w http.ResponseWriter, r *http.Request) {
	s.handleSAMLACS(w, r)
}

// HandleMetadata exposes the metadata handler for testing
func (s *Server) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	s.handleMetadata(w, r)
}

// HandleHealth exposes the health handler for testing
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	s.handleHealth(w, r)
}
