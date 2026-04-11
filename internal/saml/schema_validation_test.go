package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestSAMLResponseAgainstSchema validates the generated SAML Response against the official SAML 2.0 XSD schema
func TestSAMLResponseAgainstSchema(t *testing.T) {
	// Check if xmllint is available
	if _, err := exec.LookPath("xmllint"); err != nil {
		t.Skip("xmllint not available, skipping schema validation test")
	}

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
		"firstname":   "Test",
		"lastname":    "User",
	}

	responseXML, err := idp.CreateResponse("_test_request_id", "test@example.com", attributes)
	if err != nil {
		t.Fatalf("Failed to create response: %v", err)
	}

	// Write response to temporary file
	tmpFile, err := os.CreateTemp("", "saml-response-*.xml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Add XML declaration
	fullXML := xml.Header + string(responseXML)
	if _, err := tmpFile.WriteString(fullXML); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Pretty print the XML for debugging
	t.Logf("Generated SAML Response:\n%s", fullXML)

	// Download SAML schemas if not present
	schemaDir := "/tmp/saml-schemas"
	if err := os.MkdirAll(schemaDir, 0755); err != nil {
		t.Fatalf("Failed to create schema directory: %v", err)
	}

	schemas := map[string]string{
		"saml-schema-protocol-2.0.xsd":  "https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd",
		"saml-schema-assertion-2.0.xsd": "https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd",
		"xmldsig-core-schema.xsd":       "https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd",
		"xenc-schema.xsd":               "https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd",
	}

	for filename, url := range schemas {
		schemaPath := schemaDir + "/" + filename
		if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
			t.Logf("Downloading schema: %s", filename)
			cmd := exec.Command("curl", "-s", "-o", schemaPath, url)
			if err := cmd.Run(); err != nil {
				t.Logf("Warning: Failed to download schema %s: %v", filename, err)
			}
		}
	}

	// Validate against schema using xmllint
	schemaPath := schemaDir + "/saml-schema-protocol-2.0.xsd"
	if _, err := os.Stat(schemaPath); err == nil {
		cmd := exec.Command("xmllint", "--noout", "--schema", schemaPath, tmpFile.Name())
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("Schema validation failed:\n%s\nError: %v", string(output), err)

			// Parse the error to provide more details
			if strings.Contains(string(output), "element") {
				t.Logf("Schema validation error details: %s", string(output))
			}
		} else {
			t.Logf("Schema validation passed: %s", string(output))
		}
	} else {
		t.Skip("Schema file not available, skipping validation")
	}
}
