# Security Architecture

This document describes the security architecture, threat model, and security best practices for the SAML OIDC Bridge.

## Table of Contents

- [Security Model](#security-model)
- [Threat Model](#threat-model)
- [Security Features](#security-features)
- [Security Configuration](#security-configuration)
- [Best Practices](#best-practices)
- [Security Checklist](#security-checklist)
- [Vulnerability Reporting](#vulnerability-reporting)

## Security Model

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet (Untrusted)                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      TLS Termination                        │
│                    (Load Balancer/Ingress)                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   SAML OIDC Bridge                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Security Controls:                                  │   │
│  │  • Rate Limiting                                     │   │
│  │  • Input Validation                                  │   │
│  │  • CSRF Protection                                   │   │
│  │  • Session Management                                │   │
│  │  • Request Tracking                                  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
           │                                    │
           ▼                                    ▼
┌──────────────────────┐           ┌──────────────────────┐
│   OIDC Provider      │           │   SAML SP            │
│   (Trusted)          │           │   (Trusted)          │
└──────────────────────┘           └──────────────────────┘
```

### Authentication Flow Security

1. **SAML Request Phase**
   - Validate SAML AuthnRequest structure
   - Store request ID to prevent replay
   - Generate cryptographically secure state
   - Set secure session cookie

2. **OIDC Authentication Phase**
   - Verify state parameter (CSRF protection)
   - Validate ID token signature
   - Verify token claims (issuer, audience, expiration)
   - Extract user claims

3. **SAML Response Phase**
   - Retrieve and validate stored request
   - Map claims securely
   - Sign SAML assertion
   - Auto-submit to SP ACS

## Threat Model

### Threats and Mitigations

| Threat | Impact | Mitigation |
|--------|--------|------------|
| **Man-in-the-Middle (MITM)** | High | • Enforce HTTPS/TLS 1.2+ <br> • Set Secure flag on cookies <br> • HSTS headers |
| **Cross-Site Request Forgery (CSRF)** | High | • State parameter in OAuth flow <br> • SameSite cookie attribute <br> • Request ID tracking |
| **Session Hijacking** | High | • HttpOnly cookies <br> • Secure cookies <br> • Short session lifetime (10 min) <br> • Session binding to request ID |
| **Replay Attacks** | Medium | • Request ID tracking in database <br> • Time-based expiration <br> • One-time use enforcement |
| **Denial of Service (DoS)** | Medium | • Rate limiting (recommended) <br> • Request size limits <br> • Connection timeouts <br> • Database cleanup |
| **XML External Entity (XXE)** | High | • Disable external entity processing <br> • Use safe XML parser configuration |
| **SQL Injection** | High | • Parameterized queries (sqlc) <br> • No dynamic SQL construction |
| **Cross-Site Scripting (XSS)** | Medium | • Content Security Policy headers <br> • HTML escaping in templates <br> • X-Content-Type-Options header |
| **Clickjacking** | Low | • X-Frame-Options header <br> • CSP frame-ancestors directive |
| **Information Disclosure** | Medium | • Structured logging (no secrets) <br> • Generic error messages <br> • Secure headers |

## Security Features

### Implemented

#### 1. Cryptographic Security
- **SAML Assertion Signing**: RSA-SHA256 signatures on all assertions
- **Certificate Management**: Support for both file-based and self-signed certificates
- **State Generation**: Cryptographically secure random state for OAuth flow
- **Token Verification**: ID token signature verification using OIDC provider's JWKS

#### 2. Session Security
- **HttpOnly Cookies**: Prevents JavaScript access to session cookies
- **Secure Cookies**: Enforces HTTPS-only transmission
- **SameSite=Lax**: Protects against CSRF attacks
- **Short Lifetime**: 10-minute session expiration
- **Session Binding**: Sessions tied to specific SAML request IDs

#### 3. Request Tracking
- **Replay Prevention**: Request IDs stored and validated
- **Expiration**: Automatic cleanup of expired requests
- **One-Time Use**: Requests deleted after successful authentication

#### 4. Input Validation
- **SAML Request Parsing**: Validates AuthnRequest structure
- **OAuth State Verification**: Strict state parameter matching
- **Token Claims Validation**: Verifies issuer, audience, expiration

#### 5. Network Security
- **Timeouts**: Read (15s), Write (15s), Idle (60s)
- **Connection Limits**: Configurable via reverse proxy

### Recommended Additions

#### 1. Rate Limiting
Implement rate limiting to prevent abuse:

```go
// Example using golang.org/x/time/rate
import "golang.org/x/time/rate"

type rateLimiter struct {
    visitors map[string]*rate.Limiter
    mu       sync.RWMutex
    rate     rate.Limit
    burst    int
}

func (rl *rateLimiter) getLimiter(ip string) *rate.Limiter {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    limiter, exists := rl.visitors[ip]
    if !exists {
        limiter = rate.NewLimiter(rl.rate, rl.burst)
        rl.visitors[ip] = limiter
    }
    return limiter
}
```

**Configuration:**
```env
RATE_LIMIT_REQUESTS_PER_SECOND=10
RATE_LIMIT_BURST=20
```

#### 2. Security Headers Middleware

```go
func securityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Prevent clickjacking
        w.Header().Set("X-Frame-Options", "DENY")
        
        // Prevent MIME sniffing
        w.Header().Set("X-Content-Type-Options", "nosniff")
        
        // XSS protection
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        
        // Content Security Policy
        w.Header().Set("Content-Security-Policy", 
            "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'")
        
        // HSTS (if behind HTTPS)
        w.Header().Set("Strict-Transport-Security", 
            "max-age=31536000; includeSubDomains; preload")
        
        // Referrer policy
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        
        // Permissions policy
        w.Header().Set("Permissions-Policy", 
            "geolocation=(), microphone=(), camera=()")
        
        next.ServeHTTP(w, r)
    })
}
```

#### 3. Enhanced Input Validation

```go
// Validate and sanitize inputs
func validateSAMLRequest(req *saml.AuthnRequest) error {
    // Check request ID format
    if !isValidRequestID(req.ID) {
        return fmt.Errorf("invalid request ID format")
    }
    
    // Validate destination URL
    if !isValidURL(req.Destination) {
        return fmt.Errorf("invalid destination URL")
    }
    
    // Check for suspicious patterns
    if containsSuspiciousPatterns(req.ID) {
        return fmt.Errorf("suspicious request detected")
    }
    
    return nil
}
```

#### 4. Audit Logging

```go
// Log security-relevant events
logger.Info("security_event",
    zap.String("event_type", "authentication_success"),
    zap.String("user_id", nameID),
    zap.String("ip_address", r.RemoteAddr),
    zap.String("user_agent", r.UserAgent()),
    zap.Time("timestamp", time.Now()),
)
```

## Security Configuration

### Required Configuration

#### 1. HTTPS/TLS
**Always use HTTPS in production:**

```env
# Enable secure cookies (requires HTTPS)
SESSION_COOKIE_SECURE=true
```

**TLS Configuration (via reverse proxy):**
- Minimum TLS 1.2
- Strong cipher suites only
- HSTS enabled
- Certificate from trusted CA

#### 2. Session Security

```env
# Generate strong random secret (32+ bytes)
SESSION_COOKIE_SECRET=$(openssl rand -base64 32)

# Enable secure cookies
SESSION_COOKIE_SECURE=true

# Custom cookie name (optional)
SESSION_COOKIE_NAME=saml-oidc-bridge-session
```

#### 3. Certificate Management

**Production (File-based):**
```env
SAML_CERTIFICATE_PATH=/certs/tls.crt
SAML_PRIVATE_KEY_PATH=/certs/tls.key
```

**Development (Self-signed):**
```env
# Leave empty for auto-generation
SAML_CERTIFICATE_PATH=
SAML_PRIVATE_KEY_PATH=
```

### Optional Security Enhancements

#### 1. IP Allowlisting (via reverse proxy)

```nginx
# Nginx example
location / {
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    deny all;
    proxy_pass http://saml-oidc-bridge:8080;
}
```

#### 2. Request Size Limits

```nginx
# Nginx example
client_max_body_size 1M;
```

#### 3. Connection Limits

```nginx
# Nginx example
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_conn addr 10;
```

## Best Practices

### Deployment

1. **Use HTTPS Everywhere**
   - Terminate TLS at load balancer/ingress
   - Use certificates from trusted CA
   - Enable HSTS

2. **Secrets Management**
   - Never commit secrets to version control
   - Use secret management systems (Vault, Sealed Secrets)
   - Rotate secrets regularly
   - Use strong random values (32+ bytes)

3. **Network Segmentation**
   - Deploy in private network
   - Use network policies in Kubernetes
   - Restrict egress to OIDC provider only

4. **Monitoring and Alerting**
   - Monitor authentication failures
   - Alert on suspicious patterns
   - Track rate limit violations
   - Monitor certificate expiration

5. **Regular Updates**
   - Keep dependencies updated
   - Monitor security advisories
   - Apply security patches promptly

### Configuration

1. **Principle of Least Privilege**
   - Run as non-root user
   - Use read-only root filesystem
   - Drop unnecessary capabilities

2. **Defense in Depth**
   - Multiple layers of security
   - Fail securely (deny by default)
   - Validate all inputs

3. **Secure Defaults**
   - Short session timeouts
   - Secure cookie flags
   - Strict validation

### Operations

1. **Logging**
   - Log security events
   - Never log secrets or tokens
   - Use structured logging
   - Retain logs for audit

2. **Incident Response**
   - Have incident response plan
   - Monitor for security events
   - Regular security reviews
   - Penetration testing

3. **Backup and Recovery**
   - Regular database backups
   - Test recovery procedures
   - Secure backup storage

## Security Checklist

### Pre-Production

- [ ] HTTPS/TLS configured with valid certificate
- [ ] Strong session secret generated (32+ bytes)
- [ ] Secure cookies enabled (`SESSION_COOKIE_SECURE=true`)
- [ ] Production certificates configured (not self-signed)
- [ ] All required environment variables set
- [ ] Secrets stored in secret management system
- [ ] Network policies configured
- [ ] Resource limits set
- [ ] Monitoring and alerting configured
- [ ] Logging configured and tested

### Production

- [ ] Rate limiting enabled (via reverse proxy)
- [ ] Security headers configured
- [ ] Request size limits enforced
- [ ] Connection limits configured
- [ ] IP allowlisting (if applicable)
- [ ] Regular security updates scheduled
- [ ] Incident response plan documented
- [ ] Backup and recovery tested
- [ ] Security audit completed
- [ ] Penetration testing performed

### Ongoing

- [ ] Monitor authentication logs
- [ ] Review security alerts
- [ ] Update dependencies monthly
- [ ] Rotate secrets quarterly
- [ ] Review access logs weekly
- [ ] Test disaster recovery quarterly
- [ ] Security training for team
- [ ] Review and update security policies

## Vulnerability Reporting

If you discover a security vulnerability, please:

1. **Do NOT** open a public issue
2. Email security details to: [security@example.com]
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

## Security Contacts

- **Security Team**: security@example.com
- **PGP Key**: [Link to PGP key]

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SAML Security](https://docs.oasis-open.org/security/saml/v2.0/)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OIDC Security Considerations](https://openid.net/specs/openid-connect-core-1_0.html#Security)

## License

This security documentation is part of the SAML OIDC Bridge project and is licensed under the MIT License.
