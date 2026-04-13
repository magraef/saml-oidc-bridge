# SAML OIDC Bridge

A lightweight authentication bridge that allows SAML Service Provider (SP) applications to authenticate users via OAuth2/OpenID Connect (OIDC) Identity Providers.

## Overview

This service acts as:
- A **SAML Identity Provider (IdP)** toward your application
- An **OIDC client** toward an external IdP (Google, Azure AD, Keycloak, etc.)

It bridges the gap between SAML-based applications and modern OAuth2/OIDC identity providers.

## Features

- ✅ Single SAML SP support
- ✅ Single OIDC provider integration
- ✅ Signed SAML assertions
- ✅ Configurable attribute mapping
- ✅ SAML Single Logout (SLO) support
- ✅ **AES-256-GCM encryption** for ID tokens at rest
- ✅ Stateless session management
- ✅ SQLite-based request tracking
- ✅ Structured logging with zap
- ✅ **Security hardened** - See [SECURITY.md](.docs/SECURITY.md)

## Architecture

```
┌─────────────┐      SAML        ┌───────────────────┐     OIDC      ┌──────────────┐
│   SAML SP   │ ◄──────────────► │  saml-oidc-bridge │ ◄───────────► │  OIDC IdP    │
│ (Your App)  │   AuthnRequest   │                   │  OAuth2 Flow  │  (Google,    │
└─────────────┘   SAMLResponse   └───────────────────┘               │  Azure, etc) │
                                                                     └──────────────┘
```

## Prerequisites

- Go 1.21 or later
- OpenSSL (for certificate generation)
- An OIDC provider (Google, Azure AD, Keycloak, etc.)

## Quick Start

### 1. Configuration

The bridge uses environment variables for configuration. Create a `.env` file:

```bash
# Copy the example configuration
cp .env.example .env
```

Edit `.env` with your settings:

```bash
# OIDC Configuration
OIDC_ISSUER_URL=https://accounts.google.com
OIDC_CLIENT_ID=your-client-id.apps.googleusercontent.com
OIDC_CLIENT_SECRET=your-oidc-client-secret
OIDC_REDIRECT_URL=https://your-bridge.example.com/oidc/callback
OIDC_SCOPES=openid,profile,email

# SAML IdP Configuration
SAML_ENTITY_ID=https://your-bridge.example.com/metadata
SAML_ACS_URL=https://your-bridge.example.com/saml/login

# Service Provider Configuration
SP_ENTITY_ID=https://your-app.example.com/saml/metadata
SP_ACS_URL=https://your-app.example.com/saml/acs

# Attribute Mapping
MAPPING_NAME_ID=email
MAPPING_ATTR_EMAIL=email
MAPPING_ATTR_USERNAME=preferred_username
MAPPING_ATTR_DISPLAYNAME=name

# Session Configuration (REQUIRED: Generate strong secret)
SESSION_COOKIE_SECRET=$(openssl rand -base64 32)
SESSION_COOKIE_SECURE=false  # Set to true in production with HTTPS
SESSION_COOKIE_NAME=saml-oidc-bridge-session

# Server Configuration
SERVER_ADDRESS=:8080
DEBUG=false

# Storage Configuration
STORAGE_DATABASE_PATH=./saml-oidc-bridge.db

# Security: ID Token Encryption (RECOMMENDED for production)
# Generate with: openssl rand -hex 32
# STORAGE_ENCRYPTION_KEY=your-64-character-hex-key-here
```

**Important Security Note:** For production deployments, it's **highly recommended** to enable ID token encryption. See [ENCRYPTION.md](.docs/ENCRYPTION.md) for details.

```bash
# Generate encryption key
openssl rand -hex 32

# Add to .env
echo "STORAGE_ENCRYPTION_KEY=$(openssl rand -hex 32)" >> .env
```

### 2. Certificates (Optional for Development)

**Development (Automatic):**
The bridge automatically generates self-signed certificates if no certificate paths are provided. This is perfect for development and testing.

```bash
# No certificate configuration needed for development
# Just leave SAML_CERTIFICATE_PATH and SAML_PRIVATE_KEY_PATH empty
```

**Production (Recommended):**
Use certificates from a trusted CA or cert-manager in Kubernetes:

```bash
# Generate certificates manually
mkdir -p certs
openssl genrsa -out certs/tls.key 2048
openssl req -new -x509 -key certs/tls.key -out certs/tls.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=saml-oidc-bridge"

# Configure in .env
SAML_CERTIFICATE_PATH=./certs/tls.crt
SAML_PRIVATE_KEY_PATH=./certs/tls.key
```

For Kubernetes deployments, see [cert-manager Integration](.docs/k8s/CERT-MANAGER.md) for automatic certificate management.

### 3. Build and Run

```bash
# Build the application
go build -o saml-oidc-bridge ./cmd/server

# Run with default .env file
./saml-oidc-bridge

# Run with custom .env file
./saml-oidc-bridge -env /path/to/.env

# Run with debug logging
DEBUG=true ./saml-oidc-bridge
```

### 4. Configure Your SAML SP

Point your SAML Service Provider to use this proxy as its IdP:

- **IdP Metadata URL**: `https://your-proxy.example.com/metadata`
- **SSO URL**: `https://your-proxy.example.com/saml/login`
- **Entity ID**: Value from `saml.entity_id` in config

Download the metadata:

```bash
curl https://your-proxy.example.com/metadata > idp-metadata.xml
```

Import this metadata into your SAML SP application.

## Configuration Reference

### Environment Variables

All configuration is done via environment variables, which can be provided directly or via a `.env` file.

#### Required Variables

```bash
# OIDC Provider
OIDC_ISSUER_URL=https://accounts.google.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URL=https://your-bridge.example.com/oidc/callback

# SAML IdP
SAML_ENTITY_ID=https://your-bridge.example.com/metadata
SAML_ACS_URL=https://your-bridge.example.com/saml/login

# Service Provider
SP_ENTITY_ID=https://your-app.example.com/saml/metadata
SP_ACS_URL=https://your-app.example.com/saml/acs

# Mapping
MAPPING_NAME_ID=email

# Session (CRITICAL: Use strong random value)
SESSION_COOKIE_SECRET=$(openssl rand -base64 32)
```

#### Optional Variables with Defaults

```bash
# OIDC Scopes (default: openid,profile,email)
OIDC_SCOPES=openid,profile,email

# SAML Certificates (optional - auto-generated if not provided)
SAML_CERTIFICATE_PATH=/certs/tls.crt
SAML_PRIVATE_KEY_PATH=/certs/tls.key

# Session Configuration
SESSION_COOKIE_SECURE=false  # Set true for HTTPS
SESSION_COOKIE_NAME=saml-oidc-bridge-session

# Server Configuration
SERVER_ADDRESS=:8080
PORT=8080  # Alternative to SERVER_ADDRESS
DEBUG=false

# Storage
STORAGE_DATABASE_PATH=./saml-oidc-bridge.db
```

#### Attribute Mapping

Map OIDC claims to SAML attributes using `MAPPING_ATTR_*` variables:

```bash
MAPPING_NAME_ID=email  # OIDC claim for SAML NameID
MAPPING_ATTR_EMAIL=email
MAPPING_ATTR_USERNAME=preferred_username
MAPPING_ATTR_DISPLAYNAME=name
MAPPING_ATTR_FIRSTNAME=given_name
MAPPING_ATTR_LASTNAME=family_name
```

Common OIDC claims:
- `sub` - Subject (unique user ID)
- `email` - Email address
- `email_verified` - Email verification status
- `name` - Full name
- `given_name` - First name
- `family_name` - Last name
- `preferred_username` - Username

### OIDC Provider Setup

#### Google
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create OAuth2 credentials
3. Add authorized redirect URI: `https://your-bridge.example.com/oidc/callback`
4. Configure environment:
   ```bash
   OIDC_ISSUER_URL=https://accounts.google.com
   OIDC_CLIENT_ID=your-client-id.apps.googleusercontent.com
   OIDC_CLIENT_SECRET=your-client-secret
   ```

#### Azure AD
1. Register an application in Azure AD
2. Add redirect URI: `https://your-bridge.example.com/oidc/callback`
3. Configure environment:
   ```bash
   OIDC_ISSUER_URL=https://login.microsoftonline.com/{tenant-id}/v2.0
   OIDC_CLIENT_ID=your-application-id
   OIDC_CLIENT_SECRET=your-client-secret
   ```

#### Keycloak
1. Create a client in your realm
2. Set redirect URI: `https://your-bridge.example.com/oidc/callback`
3. Configure environment:
   ```bash
   OIDC_ISSUER_URL=https://your-keycloak.example.com/realms/{realm-name}
   OIDC_CLIENT_ID=your-client-id
   OIDC_CLIENT_SECRET=your-client-secret
   ```

### Certificate Management

#### Development (Automatic)

For development and testing, the bridge automatically generates self-signed certificates when no certificate paths are provided:

```bash
# No certificate configuration needed
# Leave SAML_CERTIFICATE_PATH and SAML_PRIVATE_KEY_PATH empty or unset
```

The bridge will log a warning about using self-signed certificates:
```
WARN: Using self-signed certificate for SAML signing (development only)
```

#### Production (File-based)

For production, provide paths to your certificates:

```bash
SAML_CERTIFICATE_PATH=/certs/tls.crt
SAML_PRIVATE_KEY_PATH=/certs/tls.key
```

Generate certificates:
```bash
# Self-signed (for testing)
openssl genrsa -out tls.key 2048
openssl req -new -x509 -key tls.key -out tls.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=saml-oidc-bridge"

# Or use certificates from a trusted CA
```

#### Kubernetes (cert-manager)

For Kubernetes deployments, use cert-manager for automatic certificate management:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: saml-oidc-bridge-cert
spec:
  secretName: saml-oidc-bridge-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - saml-bridge.example.com
```

See [cert-manager Integration Guide](.docs/k8s/CERT-MANAGER.md) for details.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/login` | GET | SAML SSO endpoint (receives AuthnRequest) |
| `/oidc/callback` | GET | OAuth2 callback endpoint |
| `/saml/acs` | POST | Not used in this flow |
| `/metadata` | GET | SAML IdP metadata |
| `/healthz` | GET | Health check endpoint |

## Authentication Flow

1. User accesses SAML SP application
2. SP redirects to `/saml/login` with SAML AuthnRequest
3. Bridge parses request and stores state
4. Bridge redirects user to OIDC provider
5. User authenticates with OIDC provider
6. OIDC provider redirects to `/oidc/callback`
7. Bridge validates tokens and extracts claims
8. Bridge generates signed SAML assertion
9. Bridge POSTs SAML Response to SP ACS endpoint
10. User is logged into the application

## Security

This bridge implements multiple layers of security to protect authentication flows. For complete security documentation, see [SECURITY.md](.docs/SECURITY.md).

### Security Features

**Authentication Security:**
- ✅ CSRF protection via OAuth state parameter
- ✅ SAML request replay prevention
- ✅ ID token signature verification
- ✅ Secure session management (HttpOnly, Secure, SameSite cookies)
- ✅ Request ID tracking and expiration

**Network Security:**
- ✅ Security headers (CSP, X-Frame-Options, HSTS, etc.)
- ✅ Connection timeouts (Read: 15s, Write: 15s, Idle: 60s)
- ✅ TLS 1.2+ enforcement (via reverse proxy)

**Input Validation:**
- ✅ SAML request structure validation
- ✅ URL validation and sanitization
- ✅ Suspicious pattern detection
- ✅ Request ID format validation
- ✅ RelayState length limits

**Cryptographic Security:**
- ✅ RSA-SHA256 SAML assertion signing
- ✅ Cryptographically secure state generation
- ✅ JWKS-based token verification

### Security Requirements

**Production Deployment:**
```env
# REQUIRED: Use HTTPS
SESSION_COOKIE_SECURE=true

# REQUIRED: Strong random secret (32+ bytes)
SESSION_COOKIE_SECRET=$(openssl rand -base64 32)

# REQUIRED: Trusted certificates
SAML_CERTIFICATE_PATH=/certs/tls.crt
SAML_PRIVATE_KEY_PATH=/certs/tls.key
```

**Recommended (via reverse proxy):**
- Rate limiting (10 req/s per IP)
- Request size limits (1MB)
- IP allowlisting (if applicable)
- WAF protection

### Security Checklist

Before deploying to production:

- [ ] HTTPS/TLS configured with valid certificate
- [ ] Strong session secret generated (32+ bytes)
- [ ] Secure cookies enabled (`SESSION_COOKIE_SECURE=true`)
- [ ] Production certificates configured (not self-signed)
- [ ] Rate limiting enabled (via reverse proxy)
- [ ] Security headers verified
- [ ] Monitoring and alerting configured
- [ ] Review [SECURITY.md](.docs/SECURITY.md) for complete checklist

### Vulnerability Reporting

If you discover a security vulnerability, please email security details to [security@example.com]. Do not open public issues for security vulnerabilities.

For more information, see [SECURITY.md](.docs/SECURITY.md).

## Troubleshooting

### Enable Debug Logging

```bash
./saml-oidc-bridge -debug
```

### Common Issues

**"Invalid SAML request"**
- Check that your SP is sending a valid SAML AuthnRequest
- Verify the SP's entity ID matches `sp.entity_id` in config

**"Authentication failed"**
- Check OIDC provider credentials
- Verify redirect URI is registered with OIDC provider
- Check OIDC provider logs

**"Missing required claim"**
- Verify the OIDC provider returns the claim specified in `mapping.name_id`
- Check that requested scopes include necessary claims

**Certificate errors**
- Ensure certificate and private key are in PEM format
- Verify file paths in configuration
- Check certificate validity: `openssl x509 -in certs/tls.crt -text -noout`

## Development

### Building from Source

```bash
# Install dependencies
go mod download

# Generate sqlc code (if schema changes)
sqlc generate

# Build
go build -o saml-oauth-proxy ./cmd/server

# Run tests
go test ./...
```

## Limitations

This is a proof-of-concept implementation with the following limitations:

- Single SAML SP support only
- Single OIDC provider
- No SAML Single Logout (SLO)
- No multi-tenancy
- No admin UI
- No dynamic configuration reload
- In-memory session storage (cookies only)

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Deployment

### Docker

#### Pre-built Images

Multi-architecture images (amd64, arm64) are automatically built and published to GitHub Container Registry:

```bash
# Pull latest image
docker pull ghcr.io/magreaf/saml-oidc-bridge:latest

# Run container
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/.env:/app/.env:ro \
  -v $(pwd)/certs:/certs:ro \
  ghcr.io/your-org/saml-oidc-bridge:latest
```

#### Build from Source

```bash
# Build image
docker build -t saml-oidc-bridge:latest .

# Run container
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/.env:/app/.env:ro \
  -v $(pwd)/certs:/certs:ro \
  -e OIDC_CLIENT_SECRET=your-secret \
  -e SESSION_COOKIE_SECRET=your-session-secret \
  saml-oidc-bridge:latest
```

### Kubernetes

#### Deployment Options

**1. Standalone Deployment** (Recommended for multiple applications)
- Dedicated service acting as SAML IdP
- Horizontal pod autoscaling
- Production-ready with cert-manager integration
- See [k8s/examples/standalone-deployment.yaml](.docs/k8s/examples/standalone-deployment.yaml)

**2. Sidecar Deployment** (Recommended for single application)
- Bridge runs alongside your application
- Simplified application code (no SAML handling)
- Shared network namespace (localhost communication)
- See [k8s/examples/sidecar-deployment.yaml](.docs/k8s/examples/sidecar-deployment.yaml)

#### Quick Start

```bash
# 1. Install cert-manager (if not already installed)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml

# 2. Create ClusterIssuer for Let's Encrypt
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF

# 3. Deploy standalone (update values in file first)
kubectl apply -f k8s/examples/standalone-deployment.yaml

# 4. Check status
kubectl get pods -n saml-oidc-bridge
kubectl get certificate -n saml-oidc-bridge
kubectl get ingress -n saml-oidc-bridge
```

#### Documentation

- **[Standalone Deployment Guide](.docs/k8s/examples/standalone-deployment.yaml)** - Production-ready standalone deployment
- **[Sidecar Deployment Guide](.docs/k8s/examples/sidecar-deployment.yaml)** - Sidecar pattern with your application
- **[cert-manager Integration](.docs/k8s/CERT-MANAGER.md)** - Automatic TLS certificate management
- **[Kubernetes README](.docs/k8s/README.md)** - Detailed deployment guide and configuration

### CI/CD

GitHub Actions workflow automatically builds and publishes multi-architecture Docker images:

- **Triggers**: Push to main/develop, tags, pull requests
- **Platforms**: linux/amd64, linux/arm64
- **Registry**: GitHub Container Registry (ghcr.io)
- **Tags**: 
  - `latest` (main branch)
  - `v1.0.0` (semantic version tags)
  - `main-abc123` (branch + commit SHA)

See [.github/workflows/docker-build.yml](.github/workflows/docker-build.yml) for workflow details.

### Environment Variables

All configuration can be provided via environment variables (takes precedence over config file):

**OIDC**: `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL`, `OIDC_SCOPES`

**SAML**: `SAML_ENTITY_ID`, `SAML_ACS_URL`, `SAML_CERTIFICATE_PATH`, `SAML_PRIVATE_KEY_PATH`

**SP**: `SP_ENTITY_ID`, `SP_ACS_URL`

**Storage**: `STORAGE_DATABASE_PATH`, `STORAGE_ENCRYPTION_KEY` (32-byte hex key for AES-256-GCM encryption)

**Mapping**: `MAPPING_NAME_ID`, `MAPPING_ATTR_<NAME>=<value>` (e.g., `MAPPING_ATTR_EMAIL=email`)

**Session**: `SESSION_COOKIE_SECRET`, `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_NAME`

**Server**: `SERVER_ADDRESS` or `PORT`

## Documentation

- **[ENCRYPTION.md](.docs/ENCRYPTION.md)** - ID token encryption guide and security best practices
- **[LOGOUT-IMPLEMENTATION.md](.docs/LOGOUT-IMPLEMENTATION.md)** - SAML Single Logout implementation details
- **[SECURITY.md](.docs/SECURITY.md)** - Security hardening guide
- **[ARCHITECTURE.md](.docs/ARCHITECTURE.md)** - System architecture and design

## Support

For issues and questions:
- Check the troubleshooting section
- Review debug logs with `-debug` flag
- Open an issue on GitHub
