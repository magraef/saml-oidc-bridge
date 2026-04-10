package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// Client handles OpenID Connect authentication
type Client struct {
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	logger       *zap.Logger
}

// UserClaims represents the user information extracted from the ID token
type UserClaims struct {
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	Name              string
	GivenName         string
	FamilyName        string
	Claims            map[string]interface{}
}

// NewClient creates a new OIDC client
func NewClient(ctx context.Context, issuerURL, clientID, clientSecret, redirectURL string, scopes []string, logger *zap.Logger) (*Client, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	logger.Info("OIDC client initialized",
		zap.String("issuer", issuerURL),
		zap.String("client_id", clientID),
		zap.Strings("scopes", scopes),
	)

	return &Client{
		provider:     provider,
		oauth2Config: oauth2Config,
		verifier:     verifier,
		logger:       logger,
	}, nil
}

// GetAuthorizationURL generates the OAuth2 authorization URL with a random state
func (c *Client) GetAuthorizationURL(state string) string {
	return c.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// GenerateState creates a cryptographically random state parameter
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HandleCallback processes the OAuth2 callback and exchanges the code for tokens
func (c *Client) HandleCallback(ctx context.Context, code string) (*UserClaims, error) {
	c.logger.Debug("Exchanging authorization code for tokens")

	// Exchange authorization code for tokens
	oauth2Token, err := c.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	// Extract ID token from OAuth2 token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	c.logger.Debug("Verifying ID token")

	// Verify ID token
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	userClaims := &UserClaims{
		Subject: idToken.Subject,
		Claims:  claims,
	}

	// Extract standard claims
	if email, ok := claims["email"].(string); ok {
		userClaims.Email = email
	}
	if emailVerified, ok := claims["email_verified"].(bool); ok {
		userClaims.EmailVerified = emailVerified
	}
	if preferredUsername, ok := claims["preferred_username"].(string); ok {
		userClaims.PreferredUsername = preferredUsername
	}
	if name, ok := claims["name"].(string); ok {
		userClaims.Name = name
	}
	if givenName, ok := claims["given_name"].(string); ok {
		userClaims.GivenName = givenName
	}
	if familyName, ok := claims["family_name"].(string); ok {
		userClaims.FamilyName = familyName
	}

	c.logger.Info("Successfully authenticated user",
		zap.String("subject", userClaims.Subject),
		zap.String("email", userClaims.Email),
	)

	return userClaims, nil
}

// GetClaimValue retrieves a claim value by key, supporting the mapping configuration
func (c *UserClaims) GetClaimValue(key string) string {
	switch key {
	case "email":
		return c.Email
	case "preferred_username":
		return c.PreferredUsername
	case "name":
		return c.Name
	case "given_name":
		return c.GivenName
	case "family_name":
		return c.FamilyName
	case "subject", "sub":
		return c.Subject
	default:
		// Try to get from raw claims
		if val, ok := c.Claims[key]; ok {
			if strVal, ok := val.(string); ok {
				return strVal
			}
		}
		return ""
	}
}

// ServeHTTP implements a simple health check for the OIDC provider
func (c *Client) HealthCheck(ctx context.Context) error {
	// Try to fetch provider configuration
	_, err := oidc.NewProvider(ctx, c.provider.Endpoint().AuthURL)
	if err != nil {
		return fmt.Errorf("OIDC provider health check failed: %w", err)
	}
	return nil
}
