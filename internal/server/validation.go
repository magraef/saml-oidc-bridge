package server

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/crewjam/saml"
	"go.uber.org/zap"
)

var (
	// requestIDPattern validates SAML request ID format
	// Must start with underscore or letter, followed by alphanumeric, underscore, hyphen, or period
	requestIDPattern = regexp.MustCompile(`^[_a-zA-Z][a-zA-Z0-9._-]*$`)

	// Suspicious patterns that might indicate injection attempts
	suspiciousPatterns = []*regexp.Regexp{
		regexp.MustCompile(`<script`),
		regexp.MustCompile(`javascript:`),
		regexp.MustCompile(`on\w+\s*=`),
		regexp.MustCompile(`<iframe`),
		regexp.MustCompile(`\.\.\/`),
		regexp.MustCompile(`%00`),
	}
)

// validateSAMLRequest performs security validation on SAML AuthnRequest
func (s *Server) validateSAMLRequest(req *saml.AuthnRequest) error {
	// Validate request ID format
	if req.ID == "" {
		return fmt.Errorf("request ID is required")
	}

	if !requestIDPattern.MatchString(req.ID) {
		s.logger.Warn("Invalid request ID format",
			zap.String("request_id", req.ID),
		)
		return fmt.Errorf("invalid request ID format")
	}

	// Check for suspicious patterns in request ID
	if containsSuspiciousPatterns(req.ID) {
		s.logger.Warn("Suspicious pattern detected in request ID",
			zap.String("request_id", req.ID),
		)
		return fmt.Errorf("suspicious request detected")
	}

	// Validate destination URL if present
	if req.Destination != "" {
		if err := s.validateURL(req.Destination); err != nil {
			s.logger.Warn("Invalid destination URL",
				zap.String("destination", req.Destination),
				zap.Error(err),
			)
			return fmt.Errorf("invalid destination URL: %w", err)
		}

		// Ensure destination matches our SAML ACS URL
		if req.Destination != s.config.SAML.ACSURL {
			s.logger.Warn("Destination URL mismatch",
				zap.String("expected", s.config.SAML.ACSURL),
				zap.String("received", req.Destination),
			)
			return fmt.Errorf("destination URL does not match expected ACS URL")
		}
	}

	// Validate AssertionConsumerServiceURL if present
	if req.AssertionConsumerServiceURL != "" {
		if err := s.validateURL(req.AssertionConsumerServiceURL); err != nil {
			s.logger.Warn("Invalid ACS URL",
				zap.String("acs_url", req.AssertionConsumerServiceURL),
				zap.Error(err),
			)
			return fmt.Errorf("invalid ACS URL: %w", err)
		}
	}

	// Validate issuer
	if req.Issuer != nil && req.Issuer.Value != "" {
		// Check if issuer matches configured SP entity ID
		if req.Issuer.Value != s.config.SP.EntityID {
			s.logger.Warn("Issuer mismatch",
				zap.String("expected", s.config.SP.EntityID),
				zap.String("received", req.Issuer.Value),
			)
			return fmt.Errorf("issuer does not match expected SP entity ID")
		}

		if containsSuspiciousPatterns(req.Issuer.Value) {
			s.logger.Warn("Suspicious pattern detected in issuer",
				zap.String("issuer", req.Issuer.Value),
			)
			return fmt.Errorf("suspicious issuer value")
		}
	}

	return nil
}

// validateURL validates that a string is a valid, safe URL
func (s *Server) validateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL is empty")
	}

	// Check for suspicious patterns
	if containsSuspiciousPatterns(urlStr) {
		return fmt.Errorf("suspicious pattern detected in URL")
	}

	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Validate scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid URL scheme: %s", parsedURL.Scheme)
	}

	// Validate host is present
	if parsedURL.Host == "" {
		return fmt.Errorf("URL host is empty")
	}

	// Check for localhost/private IPs in production
	if s.config.Session.CookieSecure {
		host := strings.ToLower(parsedURL.Hostname())
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return fmt.Errorf("localhost URLs not allowed in production")
		}
		if strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "172.16.") {
			return fmt.Errorf("private IP addresses not allowed in production")
		}
	}

	return nil
}

// validateRelayState validates the RelayState parameter
func (s *Server) validateRelayState(relayState string) error {
	// RelayState is optional
	if relayState == "" {
		return nil
	}

	// Check length (SAML spec recommends max 80 bytes)
	if len(relayState) > 80 {
		s.logger.Warn("RelayState exceeds recommended length",
			zap.Int("length", len(relayState)),
		)
		return fmt.Errorf("RelayState exceeds maximum length")
	}

	// Check for suspicious patterns
	if containsSuspiciousPatterns(relayState) {
		s.logger.Warn("Suspicious pattern detected in RelayState",
			zap.String("relay_state", relayState),
		)
		return fmt.Errorf("suspicious RelayState value")
	}

	return nil
}

// containsSuspiciousPatterns checks if a string contains any suspicious patterns
func containsSuspiciousPatterns(s string) bool {
	lowerS := strings.ToLower(s)
	for _, pattern := range suspiciousPatterns {
		if pattern.MatchString(lowerS) {
			return true
		}
	}
	return false
}

// validateOAuthState validates the OAuth state parameter
func (s *Server) validateOAuthState(state string) error {
	if state == "" {
		return fmt.Errorf("state parameter is required")
	}

	// State should be a random string, typically base64 encoded
	// Check minimum length (should be at least 16 bytes base64 encoded = 22 chars)
	if len(state) < 22 {
		s.logger.Warn("OAuth state too short",
			zap.Int("length", len(state)),
		)
		return fmt.Errorf("state parameter too short")
	}

	// Check for suspicious patterns
	if containsSuspiciousPatterns(state) {
		s.logger.Warn("Suspicious pattern detected in OAuth state")
		return fmt.Errorf("suspicious state value")
	}

	return nil
}
