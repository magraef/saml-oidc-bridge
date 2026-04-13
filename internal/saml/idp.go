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

// CreateResponse creates a SAML Response for the given user claims and returns signed XML
func (i *IdP) CreateResponse(requestID, nameID string, attributes map[string]string) ([]byte, error) {
	now := time.Now()

	// Generate unique IDs for assertion and response
	assertionID := fmt.Sprintf("_assertion_%d", now.UnixNano())
	responseID := fmt.Sprintf("_response_%d", now.UnixNano()+1)

	// Create assertion
	assertion := saml.Assertion{
		ID:           assertionID,
		IssueInstant: now,
		Version:      "2.0",
		Issuer: saml.Issuer{
			// Only set Format when it's the entity format (required for IdP issuer)
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  i.entityID,
			// NameQualifier, SPNameQualifier, SPProvidedID are optional - omit to avoid empty attributes
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
						// NotBefore is optional and should be omitted to avoid zero value serialization
						// Address is optional and should be omitted to avoid empty string serialization
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
				// FriendlyName is optional - omit to avoid empty attribute in XML
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

	// Sign the assertion - returns signed XML element
	signedAssertionElement, err := i.signAssertion(&assertion)
	if err != nil {
		return nil, fmt.Errorf("failed to sign assertion: %w", err)
	}

	// Create response structure
	response := &saml.Response{
		ID:           responseID,
		InResponseTo: requestID,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  i.spACSURL,
		Issuer: &saml.Issuer{
			Value: i.entityID,
			// NameQualifier, SPNameQualifier, Format, SPProvidedID are optional - omit to avoid empty attributes
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		// Consent is optional - leave empty to omit from XML
	}

	// The Element() method only adds attributes when they have non-empty values
	responseElement := response.Element()

	// Add the signed assertion element to the response
	// According to SAML 2.0 schema (ResponseType), the order must be:
	// 1. Issuer (from StatusResponseType, already added by Element())
	// 2. Signature (from StatusResponseType, optional - we will add this)
	// 3. Extensions (from StatusResponseType, optional - we don't use)
	// 4. Status (from StatusResponseType, already added by Element())
	// 5. Assertion/EncryptedAssertion (from ResponseType - we add this)
	//
	// Note: We sign both the Assertion AND the Response for maximum compatibility.
	responseElement.AddChild(signedAssertionElement)

	// Sign the Response element manually to control signature position
	signedResponseElement, err := i.signResponseManually(responseElement)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response: %w", err)
	}

	// Create final document
	finalDoc := etree.NewDocument()
	finalDoc.SetRoot(signedResponseElement)

	// Convert to XML bytes
	signedXML, err := finalDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed response: %w", err)
	}

	i.logger.Info("Created SAML Response",
		zap.String("response_id", response.ID),
		zap.String("in_response_to", requestID),
		zap.String("name_id", nameID),
		zap.Int("attribute_count", len(attributes)),
	)

	return signedXML, nil
}

// signAssertion signs a SAML assertion and returns the signed XML element
func (i *IdP) signAssertion(assertion *saml.Assertion) (*etree.Element, error) {
	// Build assertion element structure manually to control element ordering
	// SAML 2.0 XSD requires: Issuer, Signature, Subject, Conditions, ...
	assertionElement := assertion.Element()

	// Create key store
	keyStore := dsig.TLSCertKeyStore{
		PrivateKey:  i.privateKey,
		Certificate: [][]byte{i.certificate.Raw},
	}

	// Create signing context
	signingContext := dsig.NewDefaultSigningContext(&keyStore)
	signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	// Set C14N 1.1 canonicalization to match SP expectations
	signingContext.Canonicalizer = dsig.MakeC14N11Canonicalizer()

	// Construct the signature element (but don't append it yet)
	// This creates the complete Signature element with SignedInfo, SignatureValue, KeyInfo
	signatureElement, err := signingContext.ConstructSignature(assertionElement, true)
	if err != nil {
		return nil, fmt.Errorf("failed to construct signature: %w", err)
	}

	// Now manually insert the Signature at the correct position:
	// After Issuer (index 0), before Subject and other elements
	// This ensures the signature is in the correct position when validated
	children := assertionElement.ChildElements()

	// Find the Issuer element (should be first child)
	issuerIndex := -1
	for idx, child := range children {
		if child.Tag == "Issuer" {
			issuerIndex = idx
			break
		}
	}

	// Insert signature after Issuer (at index issuerIndex + 1)
	if issuerIndex >= 0 {
		assertionElement.InsertChildAt(issuerIndex+1, signatureElement)
	} else {
		// Fallback: insert at beginning if Issuer not found
		assertionElement.InsertChildAt(0, signatureElement)
	}

	i.logger.Debug("Assertion signed successfully with signature positioned after Issuer",
		zap.String("assertion_id", assertion.ID),
		zap.String("signature_method", "RSA-SHA256"),
		zap.Int("signature_position", issuerIndex+1),
		zap.Int("child_count", len(assertionElement.ChildElements())),
	)

	return assertionElement, nil
}

// signResponseManually signs the SAML response element with correct signature positioning
func (i *IdP) signResponseManually(responseElement *etree.Element) (*etree.Element, error) {
	// Create key store
	keyStore := dsig.TLSCertKeyStore{
		PrivateKey:  i.privateKey,
		Certificate: [][]byte{i.certificate.Raw},
	}

	// Create signing context
	signingContext := dsig.NewDefaultSigningContext(&keyStore)
	signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	// Set C14N 1.1 canonicalization to match SP expectations
	signingContext.Canonicalizer = dsig.MakeC14N11Canonicalizer()

	// Construct the signature element (but don't append it yet)
	signatureElement, err := signingContext.ConstructSignature(responseElement, true)
	if err != nil {
		return nil, fmt.Errorf("failed to construct response signature: %w", err)
	}

	// Manually insert the Signature at the correct position:
	// SAML 2.0 schema order: Issuer, Signature, Extensions (optional), Status, Assertion
	// After Issuer (index 0), before Status
	children := responseElement.ChildElements()

	// Find the Issuer element (should be first child)
	issuerIndex := -1
	for idx, child := range children {
		if child.Tag == "Issuer" {
			issuerIndex = idx
			break
		}
	}

	// Insert signature after Issuer (at index issuerIndex + 1)
	if issuerIndex >= 0 {
		responseElement.InsertChildAt(issuerIndex+1, signatureElement)
	} else {
		// Fallback: insert at beginning if Issuer not found
		responseElement.InsertChildAt(0, signatureElement)
	}

	i.logger.Debug("Response signed successfully with signature positioned after Issuer",
		zap.String("signature_method", "RSA-SHA256"),
		zap.Int("signature_position", issuerIndex+1),
		zap.Int("child_count", len(responseElement.ChildElements())),
	)

	return responseElement, nil
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
					SingleLogoutServices: []saml.Endpoint{
						{
							Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
							Location: acsURL.Scheme + "://" + acsURL.Host + "/saml/logout",
						},
						{
							Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
							Location: acsURL.Scheme + "://" + acsURL.Host + "/saml/logout",
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

// ParseLogoutRequest parses a SAML LogoutRequest from an HTTP request
func (i *IdP) ParseLogoutRequest(r *http.Request) (*saml.LogoutRequest, error) {
	// Get SAMLRequest parameter
	samlRequestEncoded := r.URL.Query().Get("SAMLRequest")
	if samlRequestEncoded == "" {
		// Try POST binding
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("failed to parse form: %w", err)
		}
		samlRequestEncoded = r.FormValue("SAMLRequest")
		if samlRequestEncoded == "" {
			return nil, fmt.Errorf("missing SAMLRequest parameter")
		}
	}

	i.logger.Debug("Parsing SAML LogoutRequest")

	// Decode base64
	compressedData, err := base64.StdEncoding.DecodeString(samlRequestEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAMLRequest: %w", err)
	}

	// Try to decompress (HTTP-Redirect binding uses deflate compression)
	// HTTP-POST binding might not be compressed
	var data []byte
	reader := flate.NewReader(bytes.NewReader(compressedData))
	data, err = io.ReadAll(io.LimitReader(reader, 1024*1024))
	reader.Close()

	if err != nil {
		// If decompression fails, try using raw data (POST binding)
		data = compressedData
	}

	// Parse XML
	var logoutRequest saml.LogoutRequest
	if err := xml.Unmarshal(data, &logoutRequest); err != nil {
		return nil, fmt.Errorf("failed to parse LogoutRequest XML: %w", err)
	}

	i.logger.Info("Parsed SAML LogoutRequest",
		zap.String("request_id", logoutRequest.ID),
		zap.String("issuer", logoutRequest.Issuer.Value),
	)

	return &logoutRequest, nil
}

// CreateLogoutResponse creates a SAML LogoutResponse
func (i *IdP) CreateLogoutResponse(requestID, statusCode string) ([]byte, error) {
	now := time.Now()
	responseID := fmt.Sprintf("_logout_response_%d", now.UnixNano())

	response := &saml.LogoutResponse{
		ID:           responseID,
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
				Value: statusCode,
			},
		},
	}

	i.logger.Info("Created SAML LogoutResponse",
		zap.String("response_id", response.ID),
		zap.String("in_response_to", requestID),
		zap.String("status", statusCode),
	)

	// Marshal to XML
	responseXML, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal LogoutResponse: %w", err)
	}

	// Add XML header
	fullXML := []byte(xml.Header + string(responseXML))

	return fullXML, nil
}
