package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"go.uber.org/zap"
)

// CertificateProvider is an interface for providing X.509 certificates and private keys
type CertificateProvider interface {
	// GetCertificate returns the X.509 certificate
	GetCertificate() (*x509.Certificate, error)

	// GetPrivateKey returns the RSA private key
	GetPrivateKey() (*rsa.PrivateKey, error)

	// Type returns the provider type name for logging
	Type() string
}

// SelfSignedCertificateProvider generates a self-signed certificate on-the-fly
// This is intended for development use only
type SelfSignedCertificateProvider struct {
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	logger      *zap.Logger
}

// NewSelfSignedCertificateProvider creates a new self-signed certificate provider
func NewSelfSignedCertificateProvider(logger *zap.Logger) (*SelfSignedCertificateProvider, error) {
	logger.Warn("Using self-signed certificate provider - NOT SUITABLE FOR PRODUCTION",
		zap.String("recommendation", "Use file-based certificates in production"),
	)

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SAML OIDC Bridge (Development)"},
			CommonName:   "saml-oidc-bridge-dev",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "saml-oidc-bridge"},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	logger.Info("Generated self-signed certificate",
		zap.String("subject", certificate.Subject.CommonName),
		zap.Time("not_before", certificate.NotBefore),
		zap.Time("not_after", certificate.NotAfter),
	)

	return &SelfSignedCertificateProvider{
		certificate: certificate,
		privateKey:  privateKey,
		logger:      logger,
	}, nil
}

// GetCertificate returns the self-signed certificate
func (p *SelfSignedCertificateProvider) GetCertificate() (*x509.Certificate, error) {
	return p.certificate, nil
}

// GetPrivateKey returns the private key
func (p *SelfSignedCertificateProvider) GetPrivateKey() (*rsa.PrivateKey, error) {
	return p.privateKey, nil
}

// Type returns the provider type
func (p *SelfSignedCertificateProvider) Type() string {
	return "self-signed"
}

// FilePathCertificateProvider loads certificates from filesystem paths
type FilePathCertificateProvider struct {
	certificatePath string
	privateKeyPath  string
	certificate     *x509.Certificate
	privateKey      *rsa.PrivateKey
	logger          *zap.Logger
}

// NewFilePathCertificateProvider creates a new file-based certificate provider
func NewFilePathCertificateProvider(certPath, keyPath string, logger *zap.Logger) (*FilePathCertificateProvider, error) {
	provider := &FilePathCertificateProvider{
		certificatePath: certPath,
		privateKeyPath:  keyPath,
		logger:          logger,
	}

	// Load certificate
	if err := provider.loadCertificate(); err != nil {
		return nil, err
	}

	// Load private key
	if err := provider.loadPrivateKey(); err != nil {
		return nil, err
	}

	logger.Info("Loaded certificate from filesystem",
		zap.String("cert_path", certPath),
		zap.String("key_path", keyPath),
		zap.String("subject", provider.certificate.Subject.CommonName),
		zap.Time("not_after", provider.certificate.NotAfter),
	)

	return provider, nil
}

// loadCertificate loads the certificate from the filesystem
func (p *FilePathCertificateProvider) loadCertificate() error {
	certPEM, err := os.ReadFile(p.certificatePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	p.certificate = cert
	return nil
}

// loadPrivateKey loads the private key from the filesystem
func (p *FilePathCertificateProvider) loadPrivateKey() error {
	keyPEM, err := os.ReadFile(p.privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	var privateKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not RSA")
		}
	default:
		return fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}

	p.privateKey = privateKey
	return nil
}

// GetCertificate returns the certificate
func (p *FilePathCertificateProvider) GetCertificate() (*x509.Certificate, error) {
	return p.certificate, nil
}

// GetPrivateKey returns the private key
func (p *FilePathCertificateProvider) GetPrivateKey() (*rsa.PrivateKey, error) {
	return p.privateKey, nil
}

// Type returns the provider type
func (p *FilePathCertificateProvider) Type() string {
	return "file-path"
}
