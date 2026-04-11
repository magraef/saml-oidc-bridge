package main

import (
	"context"
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

	// Initialize dependencies
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

	// Initialize storage with migrations
	store, err := storage.NewStore(cfg.Storage.DatabasePath, logger)
	if err != nil {
		logger.Fatal("Failed to create storage", zap.Error(err))
	}
	defer store.Close()

	// Create claims mapper
	claimsMapper := server.NewConfigClaimsMapper(&cfg.Mapping)

	// Create server with all dependencies
	srv := server.NewServer(
		oidcClient,
		samlIdP,
		samlIdP,
		samlIdP,
		store,
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

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start(cfg.Server.Address)
	}()

	// Wait for shutdown signal or error
	select {
	case err := <-errChan:
		if err != nil {
			logger.Fatal("Server error", zap.Error(err))
		}
	case sig := <-sigChan:
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
	}

	logger.Info("Shutting down gracefully")
}
