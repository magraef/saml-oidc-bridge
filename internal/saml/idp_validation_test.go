package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"math/big"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestSAMLResponseValidation tests that the generated SAML response doesn't contain empty attributes
func TestSAMLResponseValidation(t *testing.T) {
	// Create a test certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create test certificate provider
	certProvider := &testCertProvider{
		cert: cert,
		key:  privateKey,
	}

	logger := zap.NewNop()

	// Create IdP
	idp, err := NewIdP(
		"https://test-idp.example.com/metadata",
		"https://test-idp.example.com/sso",
		"https://test-sp.example.com/metadata",
		"https://test-sp.example.com/acs",
		certProvider,
		logger,
	)
	if err != nil {
		t.Fatalf("Failed to create IdP: %v", err)
	}

	// Create a SAML response
	attributes := map[string]string{
		"email":       "test@example.com",
		"username":    "testuser",
		"displayname": "Test User",
	}

	responseXML, err := idp.CreateResponse("_test_request_id", "test@example.com", attributes)
	if err != nil {
		t.Fatalf("Failed to create response: %v", err)
	}

	responseStr := string(responseXML)

	// Check for empty attributes that should not be present
	invalidPatterns := []struct {
		pattern     string
		description string
	}{
		{`NameQualifier=""`, "empty NameQualifier attribute"},
		{`SPNameQualifier=""`, "empty SPNameQualifier attribute"},
		{`SPProvidedID=""`, "empty SPProvidedID attribute"},
		{`Consent=""`, "empty Consent attribute"},
		{`Address=""`, "empty Address attribute"},
		{`FriendlyName=""`, "empty FriendlyName attribute"},
		{`NotBefore="0001-01-01`, "zero value NotBefore date"},
	}

	for _, invalid := range invalidPatterns {
		if strings.Contains(responseStr, invalid.pattern) {
			t.Errorf("Response contains %s: %s", invalid.description, invalid.pattern)
		}
	}

	// Verify the response can be unmarshaled
	var response struct {
		XMLName xml.Name `xml:"Response"`
	}
	if err := xml.Unmarshal(responseXML, &response); err != nil {
		t.Errorf("Failed to unmarshal response XML: %v", err)
	}

	// Check that required elements are present
	requiredElements := []string{
		"Response",
		"Issuer",
		"Status",
		"StatusCode",
		"Assertion",
		"Subject",
		"NameID",
		"SubjectConfirmation",
		"SubjectConfirmationData",
		"Conditions",
		"AuthnStatement",
		"AttributeStatement",
	}

	for _, elem := range requiredElements {
		if !strings.Contains(responseStr, elem) {
			t.Errorf("Response missing required element: %s", elem)
		}
	}

	// Note: We intentionally do NOT sign the Response element itself, only the Assertion.
	// This is a valid SAML 2.0 pattern and complies with the schema.
	// The Signature element should be within the Assertion, not at Response level.

	t.Logf("Generated SAML Response validation passed")
}

// testCertProvider implements CertificateProvider for testing
type testCertProvider struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func (p *testCertProvider) GetCertificate() (*x509.Certificate, error) {
	return p.cert, nil
}

func (p *testCertProvider) GetPrivateKey() (*rsa.PrivateKey, error) {
	return p.key, nil
}

func (p *testCertProvider) Type() string {
	return "test"
}
