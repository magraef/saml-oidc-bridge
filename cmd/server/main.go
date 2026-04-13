package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"saml-oidc-bridge/config"
	"saml-oidc-bridge/internal/oidc"
	"saml-oidc-bridge/internal/saml"
	"saml-oidc-bridge/internal/server"
	"saml-oidc-bridge/internal/storage"

	"go.uber.org/zap"
)

func main() {
	// Parse command line flags
	envPath := flag.String("env", ".env", "Path to .env file")
	flag.Parse()

	// Load configuration (from .env file and environment variables)
	cfg, err := config.Load(*envPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger based on config
	var logger *zap.Logger

	if cfg.Server.Debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting saml-oidc-bridge",
		zap.String("env", *envPath),
		zap.Bool("debug", cfg.Server.Debug),
		zap.String("address", cfg.Server.Address),
	)

	logger.Info("Configuration loaded successfully")

	// Initialize dependencies with cancellable context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		logger.Fatal("Failed to create OIDC client", zap.Error(err))
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
			logger.Fatal("Failed to create file-path certificate provider", zap.Error(err))
		}
	} else {
		certProvider, err = saml.NewSelfSignedCertificateProvider(logger)
		if err != nil {
			logger.Fatal("Failed to create self-signed certificate provider", zap.Error(err))
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
		logger.Fatal("Failed to create SAML IdP", zap.Error(err))
	}

	// Parse encryption key if provided
	var encryptionKey []byte
	if cfg.Storage.EncryptionKey != "" {
		encryptionKey, err = parseEncryptionKey(cfg.Storage.EncryptionKey)
		if err != nil {
			logger.Fatal("Failed to parse encryption key", zap.Error(err))
		}
	}

	// Initialize storage with migrations and cleanup goroutine
	store, err := storage.NewStore(ctx, cfg.Storage.DatabasePath, encryptionKey, logger)
	if err != nil {
		logger.Fatal("Failed to create storage", zap.Error(err))
	}
	defer store.Close()

	// Create claims mapper
	claimsMapper := server.NewConfigClaimsMapper(&cfg.Mapping, logger)

	// Create server with all dependencies
	srv := server.NewServer(
		ctx,
		oidcClient,
		samlIdP,
		samlIdP,
		samlIdP,
		store,
		claimsMapper,
		store,
		logger,
		cfg.Session.CookieName,
		cfg.Session.CookieSecure,
		cfg.SP.EntityID,
		cfg.SP.ACSURL,
		80, // Default SAML spec recommendation for max RelayState length
	)
	defer srv.Close()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start(ctx, cfg.Server.Address)
	}()

	// Wait for shutdown signal or server error
	select {
	case err := <-errChan:
		if err != nil {
			logger.Fatal("Server error", zap.Error(err))
		}
	case sig := <-sigChan:
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))

		// Cancel context to trigger graceful shutdown
		cancel()

		// Wait for server to finish shutting down
		if err := <-errChan; err != nil {
			logger.Error("Server shutdown error", zap.Error(err))
		}
	}

	logger.Info("Shutdown complete")
}

// parseEncryptionKey converts a hex-encoded string to a 32-byte key
func parseEncryptionKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}
