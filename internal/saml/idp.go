package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"go.uber.org/zap"
)

// IdP represents a SAML Identity Provider
type IdP struct {
	certProvider CertificateProvider
	certificate  *x509.Certificate
	privateKey   *rsa.PrivateKey
	entityID     string
	acsURL       string
	spEntityID   string
	spACSURL     string
	logger       *zap.Logger
}

// NewIdP creates a new SAML Identity Provider
func NewIdP(entityID, acsURL, spEntityID, spACSURL string, certProvider CertificateProvider, logger *zap.Logger) (*IdP, error) {
	// Get certificate from provider
	cert, err := certProvider.GetCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Get private key from provider
	privateKey, err := certProvider.GetPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	logger.Info("SAML IdP initialized",
		zap.String("entity_id", entityID),
		zap.String("acs_url", acsURL),
		zap.String("sp_entity_id", spEntityID),
		zap.String("sp_acs_url", spACSURL),
		zap.String("certificate_provider", certProvider.Type()),
	)

	return &IdP{
		certProvider: certProvider,
		certificate:  cert,
		privateKey:   privateKey,
		entityID:     entityID,
		acsURL:       acsURL,
		spEntityID:   spEntityID,
		spACSURL:     spACSURL,
		logger:       logger,
	}, nil
}

// ParseAuthnRequest parses a SAML AuthnRequest from an HTTP request
func (i *IdP) ParseAuthnRequest(r *http.Request) (*saml.AuthnRequest, error) {
	// Get SAMLRequest parameter
	samlRequestEncoded := r.URL.Query().Get("SAMLRequest")
	if samlRequestEncoded == "" {
		return nil, fmt.Errorf("missing SAMLRequest parameter")
	}

	i.logger.Debug("Parsing SAML AuthnRequest")

	// Decode base64
	compressedData, err := base64.StdEncoding.DecodeString(samlRequestEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAMLRequest: %w", err)
	}

	// Decompress (HTTP-Redirect binding uses deflate compression)
	reader := flate.NewReader(bytes.NewReader(compressedData))
	defer reader.Close()

	data, err := io.ReadAll(io.LimitReader(reader, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to decompress SAMLRequest: %w", err)
	}

	// Parse XML
	var authnRequest saml.AuthnRequest
	if err := xml.Unmarshal(data, &authnRequest); err != nil {
		return nil, fmt.Errorf("failed to parse AuthnRequest XML: %w", err)
	}

	i.logger.Info("Parsed SAML AuthnRequest",
		zap.String("request_id", authnRequest.ID),
		zap.String("issuer", authnRequest.Issuer.Value),
	)

	return &authnRequest, nil
}

// GetRelayState extracts the RelayState from the request
func (i *IdP) GetRelayState(r *http.Request) string {
	return r.URL.Query().Get("RelayState")
}

// CreateResponse creates a SAML Response for the given user claims
func (i *IdP) CreateResponse(requestID, nameID string, attributes map[string]string) (*saml.Response, error) {
	now := time.Now()

	// Create assertion
	assertion := saml.Assertion{
		ID:           fmt.Sprintf("id-%d", now.UnixNano()),
		IssueInstant: now,
		Version:      "2.0",
		Issuer: saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  i.entityID,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				Value:  nameID,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						InResponseTo: requestID,
						NotOnOrAfter: now.Add(5 * time.Minute),
						Recipient:    i.spACSURL,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    now.Add(-5 * time.Minute),
			NotOnOrAfter: now.Add(5 * time.Minute),
			AudienceRestrictions: []saml.AudienceRestriction{
				{
					Audience: saml.Audience{
						Value: i.spEntityID,
					},
				},
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnInstant: now,
				SessionIndex: fmt.Sprintf("session-%d", now.UnixNano()),
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					},
				},
			},
		},
	}

	// Add attributes
	if len(attributes) > 0 {
		var attrs []saml.Attribute

		for name, value := range attributes {
			attrs = append(attrs, saml.Attribute{
				Name:       name,
				NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values: []saml.AttributeValue{
					{
						Type:  "xs:string",
						Value: value,
					},
				},
			})
		}

		assertion.AttributeStatements = []saml.AttributeStatement{
			{
				Attributes: attrs,
			},
		}
	}

	// Create response
	response := &saml.Response{
		ID:           fmt.Sprintf("id-%d", now.UnixNano()),
		InResponseTo: requestID,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  i.spACSURL,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  i.entityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
	}

	// Sign the assertion
	signedAssertion, err := i.signAssertion(&assertion)
	if err != nil {
		return nil, fmt.Errorf("failed to sign assertion: %w", err)
	}

	// Add signed assertion to response
	response.Assertion = signedAssertion

	i.logger.Info("Created SAML Response",
		zap.String("response_id", response.ID),
		zap.String("in_response_to", requestID),
		zap.String("name_id", nameID),
		zap.Int("attribute_count", len(attributes)),
	)

	return response, nil
}

// signAssertion signs a SAML assertion using XML digital signatures
func (i *IdP) signAssertion(assertion *saml.Assertion) (*saml.Assertion, error) {
	// Marshal assertion to XML
	assertionXML, err := xml.Marshal(assertion)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal assertion: %w", err)
	}

	// Parse XML into etree document
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(assertionXML); err != nil {
		return nil, fmt.Errorf("failed to parse assertion XML: %w", err)
	}

	// Create key store
	keyStore := dsig.TLSCertKeyStore{
		PrivateKey:  i.privateKey,
		Certificate: [][]byte{i.certificate.Raw}, // Include certificate for verification
	}

	// Create signing context
	signingContext := dsig.NewDefaultSigningContext(&keyStore)
	signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod)

	// Sign the document
	signedElement, err := signingContext.SignEnveloped(doc.Root())
	if err != nil {
		return nil, fmt.Errorf("failed to sign assertion: %w", err)
	}

	// Create new document with signed element
	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signedElement)

	// Convert back to XML bytes
	signedXML, err := signedDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed assertion: %w", err)
	}

	// Unmarshal back to assertion struct
	var signedAssertion saml.Assertion
	if err := xml.Unmarshal(signedXML, &signedAssertion); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed assertion: %w", err)
	}

	i.logger.Debug("Assertion signed successfully",
		zap.String("assertion_id", assertion.ID),
		zap.String("signature_method", "RSA-SHA256"),
	)

	return &signedAssertion, nil
}

// SignResponse signs the SAML response using XML digital signatures
func (i *IdP) SignResponse(response *saml.Response) error {
	// Marshal response to XML
	responseXML, err := xml.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Parse XML into etree document
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(responseXML); err != nil {
		return fmt.Errorf("failed to parse response XML: %w", err)
	}

	// Create key store
	keyStore := dsig.TLSCertKeyStore{
		PrivateKey:  i.privateKey,
		Certificate: [][]byte{i.certificate.Raw}, // Include certificate for verification
	}

	// Create signing context
	signingContext := dsig.NewDefaultSigningContext(&keyStore)
	signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod)

	// Sign the document
	signedElement, err := signingContext.SignEnveloped(doc.Root())
	if err != nil {
		return fmt.Errorf("failed to sign response: %w", err)
	}

	// Create new document with signed element
	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signedElement)

	// Convert back to XML bytes
	signedXML, err := signedDoc.WriteToBytes()
	if err != nil {
		return fmt.Errorf("failed to serialize signed response: %w", err)
	}

	// Unmarshal back to response struct
	if err := xml.Unmarshal(signedXML, response); err != nil {
		return fmt.Errorf("failed to unmarshal signed response: %w", err)
	}

	i.logger.Debug("Response signed successfully",
		zap.String("response_id", response.ID),
		zap.String("signature_method", "RSA-SHA256"),
	)

	return nil
}

// GetMetadata returns the SAML IdP metadata
func (i *IdP) GetMetadata() (*saml.EntityDescriptor, error) {
	acsURL, err := url.Parse(i.acsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ACS URL: %w", err)
	}

	// Encode certificate to base64
	certBase64 := base64.StdEncoding.EncodeToString(i.certificate.Raw)

	metadata := &saml.EntityDescriptor{
		EntityID:   i.entityID,
		ValidUntil: time.Now().Add(365 * 24 * time.Hour),
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{
												Data: certBase64,
											},
										},
									},
								},
							},
						},
					},
					NameIDFormats: []saml.NameIDFormat{
						"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
						"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
						"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
						Location: acsURL.String(),
					},
				},
			},
		},
	}

	i.logger.Debug("Generated SAML IdP metadata")
	return metadata, nil
}
