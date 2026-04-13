# SAML-OIDC Bridge

A lightweight authentication bridge that enables SAML Service Provider applications to authenticate users via OAuth2/OpenID Connect Identity Providers.

## Overview

This service acts as a SAML Identity Provider (IdP) for your application while authenticating users through modern OAuth2/OIDC providers like Google, Azure AD, or Keycloak.

**Architecture:**
```
┌─────────────┐      SAML        ┌───────────────────┐     OIDC      ┌──────────────┐
│   SAML SP   │ ◄──────────────► │  SAML-OIDC Bridge │ ◄───────────► │  OIDC IdP    │
│ (Your App)  │   AuthnRequest   │                   │  OAuth2 Flow  │  (Google,    │
└─────────────┘   SAMLResponse   └───────────────────┘               │  Azure, etc) │
                                                                      └──────────────┘
```

## Features

- **Simplified Configuration** - Single base URL derives all SAML and OIDC endpoints
- **Security Hardened** - CSRF protection, request replay prevention, secure sessions, AES-256-GCM encryption for ID tokens
- **Flexible Attribute Mapping** - Map OIDC claims to SAML attributes
- **SAML 2.0 Compliant** - Signed assertions and responses with RSA-SHA256 + C14N 1.1
- **Single Logout Support** - SAML SLO implementation
- **Certificate support** - Self-signed certs for development, cert-manager for production

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/login` | GET | SAML SSO endpoint (receives AuthnRequest) |
| `/saml/logout` | GET/POST | SAML Single Logout endpoint |
| `/oidc/callback` | GET | OAuth2 callback endpoint |
| `/metadata` | GET | SAML IdP metadata |
| `/healthz` | GET | Health check endpoint |

**Automatically Derived Endpoints:**
From `IDP_URL=https://saml-bridge.example.com`:
- OIDC Redirect: `https://saml-bridge.example.com/oidc/callback`
- SAML Entity ID: `https://saml-bridge.example.com`
- SAML Metadata: `https://saml-bridge.example.com/metadata`
- SAML Login: `https://saml-bridge.example.com/saml/login`
- SAML Logout: `https://saml-bridge.example.com/saml/logout`


### Configure Your Application

Point your SAML Service Provider to the bridge:

- **IdP Metadata URL**: `https://saml-bridge.example.com/metadata`
- **SSO URL**: `https://saml-bridge.example.com/saml/login`
- **Entity ID**: `https://saml-bridge.example.com`

Download and import the metadata:
```bash
curl https://saml-bridge.example.com/metadata > idp-metadata.xml
```

## OIDC Provider Setup

1. Create OAuth2 credentials for your proivder
2. Add redirect URI: `https://saml-bridge.example.com/oidc/callback`
3. Configure:
   ```bash
   OIDC_ISSUER_URL=https://oidc.url
   OIDC_CLIENT_ID=your-client-id
   OIDC_CLIENT_SECRET=your-client-secret
   ```
   
## Configuration Reference

### Required Environment Variables

```bash
# OIDC Provider
OIDC_ISSUER_URL          # OIDC provider URL
OIDC_CLIENT_ID           # OAuth2 client ID
OIDC_CLIENT_SECRET       # OAuth2 client secret

# Bridge Base URL
IDP_URL                  # Base URL for all SAML/OIDC endpoints

# Service Provider
SP_ENTITY_ID             # Your application's SAML entity ID
SP_ACS_URL               # Your application's assertion consumer service URL

# Mapping
MAPPING_NAME_ID          # OIDC claim for SAML NameID (e.g., "email")

# Session
SESSION_COOKIE_SECRET    # Strong random secret (32+ bytes)
```

### Optional Environment Variables

```bash
# OIDC
OIDC_SCOPES=openid,profile,email  # Default scopes

# SAML Certificates (auto-generated if not provided)
SAML_CERTIFICATE_PATH=/certs/tls.crt
SAML_PRIVATE_KEY_PATH=/certs/tls.key

# Session
SESSION_COOKIE_SECURE=true        # Use secure cookies (HTTPS)
SESSION_COOKIE_NAME=saml-oidc-bridge-session

# Server
SERVER_ADDRESS=:8080              # Listen address
DEBUG=false                       # Enable debug logging

# Storage
STORAGE_DATABASE_PATH=./saml-oidc-bridge.db
STORAGE_ENCRYPTION_KEY=...        # 64-char hex key for AES-256-GCM
```

### Attribute Mapping

Map OIDC claims to SAML attributes using `MAPPING_ATTR_*` variables:

```bash
MAPPING_NAME_ID=email              # SAML NameID
MAPPING_ATTR_EMAIL=email
MAPPING_ATTR_USERNAME=preferred_username
MAPPING_ATTR_DISPLAYNAME=name
MAPPING_ATTR_FIRSTNAME=given_name
MAPPING_ATTR_LASTNAME=family_name
```

**Common OIDC Claims:**
- `sub` - Unique user identifier
- `email` - Email address
- `email_verified` - Email verification status
- `name` - Full name
- `given_name` - First name
- `family_name` - Last name
- `preferred_username` - Username

## Authentication Flow

1. User accesses SAML SP application
2. SP redirects to bridge with SAML AuthnRequest
3. Bridge stores request state and redirects to OIDC provider
4. User authenticates with OIDC provider
5. OIDC provider redirects back to bridge with authorization code
6. Bridge exchanges code for ID token and validates it
7. Bridge generates signed SAML assertion with mapped attributes
8. Bridge POSTs SAML Response to SP's ACS endpoint
9. User is authenticated in the application

## Security

### Security Features

**Authentication:**
- CSRF protection via OAuth state parameter
- SAML request replay prevention with expiration
- ID token signature verification (JWKS)
- Secure session management (HttpOnly, Secure, SameSite cookies)

**Cryptography:**
- RSA-SHA256 SAML assertion signing
- C14N 1.1 canonicalization for SAML 2.0 compliance
- AES-256-GCM encryption for stored ID tokens (optional)
- Cryptographically secure random state generation

**Input Validation:**
- SAML request structure validation
- URL validation and sanitization
- Request ID format validation
- RelayState length limits

**Network Security:**
- Security headers (CSP, X-Frame-Options, HSTS)
- Connection timeouts (Read: 15s, Write: 15s, Idle: 60s)
- TLS 1.2+ enforcement (via reverse proxy)

### Production Checklist

Before deploying to production:

- [ ] HTTPS/TLS configured with valid certificate
- [ ] Strong session secret generated: `SESSION_COOKIE_SECRET=$(openssl rand -base64 32)`
- [ ] Secure cookies enabled: `SESSION_COOKIE_SECURE=true`
- [ ] ID token encryption enabled: `STORAGE_ENCRYPTION_KEY=$(openssl rand -hex 32)`
- [ ] Production certificates configured (not self-signed)
- [ ] Rate limiting enabled (via reverse proxy)

## Certificate Management

### Development (Automatic)

No configuration needed. The bridge automatically generates self-signed certificates:

```bash
# Leave certificate paths empty
# SAML_CERTIFICATE_PATH=
# SAML_PRIVATE_KEY_PATH=
```

### Production (File-based)

Provide paths to your certificates:

```bash
SAML_CERTIFICATE_PATH=/certs/tls.crt
SAML_PRIVATE_KEY_PATH=/certs/tls.key
```

Generate certificates:
```bash
# Self-signed (testing only)
openssl genrsa -out tls.key 2048
openssl req -new -x509 -key tls.key -out tls.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=saml-oidc-bridge"
```

### Kubernetes (cert-manager)

Use cert-manager for automatic certificate management.

## Deployment

### Docker

**With Environment Variables:**
```bash
docker run -d \
  -p 8080:8080 \
  -e OIDC_ISSUER_URL=https://accounts.google.com \
  -e OIDC_CLIENT_ID=your-client-id.apps.googleusercontent.com \
  -e OIDC_CLIENT_SECRET=your-client-secret \
  -e IDP_URL=https://saml-bridge.example.com \
  -e SP_ENTITY_ID=https://your-app.example.com/saml/metadata \
  -e SP_ACS_URL=https://your-app.example.com/saml/acs \
  -e MAPPING_NAME_ID=email \
  -e SESSION_COOKIE_SECRET=$(openssl rand -base64 32) \
  -e SESSION_COOKIE_SECURE=true \
  ghcr.io/magraef/saml-oidc-bridge:latest
```

### Kubernetes

Samples for kubernetes with and without cert-manager are provided [here](.docs/k8s/).

## Troubleshooting

### Enable Debug Logging

```bash
DEBUG=true ./saml-oidc-bridge
```

### Common Issues

**"Invalid SAML request"**
- Verify SP's entity ID matches `SP_ENTITY_ID` in config
- Check SAML request is properly formatted
- Enable debug logging to see request details

**"Authentication failed"**
- Verify OIDC provider credentials
- Check redirect URI is registered: `{IDP_URL}/oidc/callback`
- Review OIDC provider logs

**"Missing required claim"**
- Verify OIDC provider returns the claim specified in `MAPPING_NAME_ID`
- Check requested scopes include necessary claims
- Use debug logging to see received claims

**Certificate errors**
- Ensure certificate and private key are in PEM format
- Verify file paths in configuration
- Check certificate validity: `openssl x509 -in tls.crt -text -noout`

**"Invalid Signature on SAML Response"**
- Verify SP supports RSA-SHA256 signature algorithm
- Check SP supports C14N 1.1 canonicalization
- Ensure certificates are properly configured

## Limitations

- Single SAML SP support (one application per bridge instance)
- Single OIDC provider per instance
- No multi-tenancy
- No admin UI
- No dynamic configuration reload

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## License

MIT License - see LICENSE file for details