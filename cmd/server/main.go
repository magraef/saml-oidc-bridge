package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"saml-oidc-bridge/internal/server"
	"syscall"

	"saml-oidc-bridge/config"

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

	// Create server
	srv, err := server.NewServer(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to create server", zap.Error(err))
	}
	defer srv.Close()

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
