# Kubernetes Deployment Guide

This directory contains Kubernetes manifests for deploying saml-oidc-bridge.

## Prerequisites

- Kubernetes cluster (1.19+)
- kubectl configured
- Ingress controller (nginx recommended)
- cert-manager (optional, for automatic TLS)

## Quick Start

### 1. Build Docker Image

```bash
# Build the image
docker build -t saml-oidc-bridge:latest .

# Tag for your registry
docker tag saml-oauth-proxy:latest your-registry.com/saml-oidc-bridge:latest

# Push to registry
docker push your-registry.com/saml-oidc-bridge:latest
```

### 2. Generate Certificates

```bash
# Generate certificates for SAML signing
openssl genrsa -out tls.key 2048
openssl req -new -x509 -key tls.key -out tls.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=saml-oidc-bridge"

# Create Kubernetes secret
kubectl create secret tls saml-oidc-bridge-certs \
  --cert=tls.crt \
  --key=tls.key \
  -n saml-oidc-bridge
```

### 3. Configure Secrets

Edit `deployment.yaml` and update the secrets:

```bash
# Generate a random session secret
openssl rand -base64 32

# Update the secrets in deployment.yaml
kubectl apply -f deployment.yaml
```

### 4. Deploy

```bash
# Apply all manifests
kubectl apply -f deployment.yaml

# Check deployment status
kubectl get pods -n saml-oidc-bridge
kubectl logs -f deployment/saml-oauth-proxy -n saml-oidc-bridge
```

## Configuration

### Environment Variables

All configuration can be provided via environment variables:

#### OIDC Configuration
- `OIDC_ISSUER_URL` - OIDC provider issuer URL
- `OIDC_CLIENT_ID` - OAuth2 client ID
- `OIDC_CLIENT_SECRET` - OAuth2 client secret (from secret)
- `OIDC_REDIRECT_URL` - OAuth2 redirect URL
- `OIDC_SCOPES` - Comma-separated list of scopes

#### SAML Configuration
- `SAML_ENTITY_ID` - SAML IdP entity ID
- `SAML_ACS_URL` - SAML IdP ACS URL
- `SAML_CERTIFICATE_PATH` - Path to certificate (mounted from secret)
- `SAML_PRIVATE_KEY_PATH` - Path to private key (mounted from secret)

#### SP Configuration
- `SP_ENTITY_ID` - Service Provider entity ID
- `SP_ACS_URL` - Service Provider ACS URL

#### Mapping Configuration
- `MAPPING_NAME_ID` - OIDC claim for SAML NameID
- `MAPPING_ATTR_<NAME>` - Map SAML attribute to OIDC claim
  - Example: `MAPPING_ATTR_EMAIL=email`

#### Session Configuration
- `SESSION_COOKIE_SECRET` - Cookie signing secret (from secret)
- `SESSION_COOKIE_SECURE` - Use secure cookies (true/false)
- `SESSION_COOKIE_NAME` - Cookie name

#### Server Configuration
- `SERVER_ADDRESS` - Listen address (default: :8080)
- `PORT` - Alternative to SERVER_ADDRESS

#### Storage Configuration
- `STORAGE_DATABASE_PATH` - SQLite database path

### Using ConfigMap

You can also provide a `config.yaml` file via ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: saml-oidc-bridge-config
  namespace: saml-oidc-bridge
data:
  config.yaml: |
    oidc:
      issuer_url: https://accounts.google.com
      # ... rest of config
```

Environment variables will override ConfigMap values.

## Ingress Configuration

The deployment includes an Ingress resource. Update the following:

1. **Hostname**: Change `proxy.example.com` to your domain
2. **TLS**: Configure cert-manager or provide your own TLS secret
3. **Ingress Class**: Adjust if not using nginx

```yaml
spec:
  ingressClassName: nginx  # Change if using different ingress
  tls:
  - hosts:
    - your-domain.com
    secretName: saml-oidc-bridge-tls
```

## Health Checks

The deployment includes liveness and readiness probes:

- **Liveness**: `/healthz` - Checks if the application is running
- **Readiness**: `/healthz` - Checks if the application is ready to serve traffic

## Scaling

Scale the deployment:

```bash
kubectl scale deployment saml-oauth-proxy -n saml-oidc-bridge --replicas=3
```

## Monitoring

View logs:

```bash
# All pods
kubectl logs -f -l app=saml-oauth-proxy -n saml-oidc-bridge

# Specific pod
kubectl logs -f saml-oauth-proxy-<pod-id> -n saml-oidc-bridge
```

Check metrics:

```bash
kubectl top pods -n saml-oidc-bridge
```

## Troubleshooting

### Pod not starting

```bash
kubectl describe pod -l app=saml-oauth-proxy -n saml-oidc-bridge
kubectl logs -l app=saml-oauth-proxy -n saml-oidc-bridge
```

### Configuration issues

```bash
# Check environment variables
kubectl exec -it deployment/saml-oauth-proxy -n saml-oidc-bridge -- env | grep -E "OIDC|SAML|SP|MAPPING"

# Check mounted files
kubectl exec -it deployment/saml-oauth-proxy -n saml-oidc-bridge -- ls -la /certs /config
```

### Certificate issues

```bash
# Verify certificate secret
kubectl get secret saml-oauth-proxy-certs -n saml-oidc-bridge -o yaml

# Check certificate validity
kubectl exec -it deployment/saml-oauth-proxy -n saml-oidc-bridge -- \
  openssl x509 -in /certs/tls.crt -text -noout
```

## Security Considerations

1. **Secrets Management**: Use external secret management (e.g., Vault, Sealed Secrets)
2. **Network Policies**: Restrict pod-to-pod communication
3. **RBAC**: Apply least-privilege access
4. **Pod Security**: The deployment uses security contexts and read-only root filesystem
5. **TLS**: Always use HTTPS in production (configure Ingress TLS)

## Example: Google OAuth

```yaml
env:
- name: OIDC_ISSUER_URL
  value: "https://accounts.google.com"
- name: OIDC_CLIENT_ID
  value: "123456789.apps.googleusercontent.com"
- name: OIDC_REDIRECT_URL
  value: "https://proxy.example.com/oidc/callback"
- name: OIDC_SCOPES
  value: "openid,profile,email"
```

## Example: Azure AD

```yaml
env:
- name: OIDC_ISSUER_URL
  value: "https://login.microsoftonline.com/<tenant-id>/v2.0"
- name: OIDC_CLIENT_ID
  value: "<application-id>"
- name: OIDC_REDIRECT_URL
  value: "https://proxy.example.com/oidc/callback"
- name: OIDC_SCOPES
  value: "openid,profile,email"
```

## Cleanup

```bash
kubectl delete namespace saml-oidc-bridge
```
