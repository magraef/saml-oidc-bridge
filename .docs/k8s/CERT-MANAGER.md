# cert-manager Integration Guide

This guide explains how to use cert-manager to automatically manage TLS certificates for the SAML OIDC Bridge.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installing cert-manager](#installing-cert-manager)
- [Configuring Issuers](#configuring-issuers)
- [Certificate Management](#certificate-management)
- [Troubleshooting](#troubleshooting)

## Overview

cert-manager automates the management and issuance of TLS certificates in Kubernetes. For SAML OIDC Bridge, certificates are used for:

1. **SAML Assertion Signing**: Certificates used to sign SAML assertions
2. **Ingress TLS**: HTTPS certificates for the ingress endpoint

## Prerequisites

- Kubernetes cluster (1.19+)
- kubectl configured
- Helm 3.x (recommended for installation)
- Domain name with DNS configured

## Installing cert-manager

### Option 1: Using Helm (Recommended)

```bash
# Add the Jetstack Helm repository
helm repo add jetstack https://charts.jetstack.io
helm repo update

# Install cert-manager with CRDs
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.14.0 \
  --set installCRDs=true
```

### Option 2: Using kubectl

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml
```

### Verify Installation

```bash
# Check cert-manager pods are running
kubectl get pods -n cert-manager

# Expected output:
# NAME                                       READY   STATUS    RESTARTS   AGE
# cert-manager-7d9f8c8d4-xxxxx              1/1     Running   0          1m
# cert-manager-cainjector-5c5695c4b-xxxxx   1/1     Running   0          1m
# cert-manager-webhook-7d9f8c8d4-xxxxx      1/1     Running   0          1m
```

## Configuring Issuers

cert-manager uses Issuers or ClusterIssuers to obtain certificates. ClusterIssuers work across all namespaces.

### Let's Encrypt Production Issuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    # Let's Encrypt production server
    server: https://acme-v02.api.letsencrypt.org/directory
    
    # Email for certificate expiration notifications
    email: admin@example.com
    
    # Secret to store ACME account private key
    privateKeySecretRef:
      name: letsencrypt-prod
    
    # HTTP-01 challenge solver
    solvers:
    - http01:
        ingress:
          class: nginx
```

### Let's Encrypt Staging Issuer (for testing)

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    # Let's Encrypt staging server (for testing)
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-staging
    solvers:
    - http01:
        ingress:
          class: nginx
```

### DNS-01 Challenge (for wildcard certificates)

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-dns
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-dns
    solvers:
    # Example: CloudFlare DNS
    - dns01:
        cloudflare:
          email: admin@example.com
          apiTokenSecretRef:
            name: cloudflare-api-token
            key: api-token
```

### Apply Issuers

```bash
# Create the issuer configuration
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

# Verify issuer is ready
kubectl get clusterissuer letsencrypt-prod
```

## Certificate Management

### Method 1: Certificate Resource (Recommended)

Create a Certificate resource that cert-manager will manage:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: saml-oidc-bridge-cert
  namespace: saml-oidc-bridge
spec:
  # Secret where certificate will be stored
  secretName: saml-oidc-bridge-tls
  
  # Reference to issuer
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  
  # Domain names for certificate
  dnsNames:
    - saml-bridge.example.com
  
  # Certificate usages
  usages:
    - digital signature
    - key encipherment
    - server auth
  
  # Certificate lifetime
  duration: 2160h # 90 days
  renewBefore: 720h # 30 days before expiration
```

Apply the certificate:

```bash
kubectl apply -f certificate.yaml

# Check certificate status
kubectl get certificate -n saml-oidc-bridge
kubectl describe certificate saml-oidc-bridge-cert -n saml-oidc-bridge
```

### Method 2: Ingress Annotation (Automatic)

Add annotation to Ingress resource:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: saml-oidc-bridge
  namespace: saml-oidc-bridge
  annotations:
    # This annotation triggers automatic certificate creation
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - saml-bridge.example.com
    secretName: saml-bridge-tls  # cert-manager will create this
  rules:
  - host: saml-bridge.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: saml-oidc-bridge
            port:
              number: 80
```

## Using Certificates with SAML OIDC Bridge

### Standalone Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: saml-oidc-bridge
  namespace: saml-oidc-bridge
spec:
  template:
    spec:
      containers:
      - name: saml-oidc-bridge
        image: ghcr.io/your-org/saml-oidc-bridge:latest
        env:
        - name: SAML_CERTIFICATE_PATH
          value: "/certs/tls.crt"
        - name: SAML_PRIVATE_KEY_PATH
          value: "/certs/tls.key"
        volumeMounts:
        - name: certs
          mountPath: /certs
          readOnly: true
      volumes:
      - name: certs
        secret:
          secretName: saml-oidc-bridge-tls  # Created by cert-manager
```

### Sidecar Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: myapp
spec:
  template:
    spec:
      containers:
      - name: saml-oidc-bridge
        image: ghcr.io/your-org/saml-oidc-bridge:latest
        env:
        - name: SAML_CERTIFICATE_PATH
          value: "/certs/tls.crt"
        - name: SAML_PRIVATE_KEY_PATH
          value: "/certs/tls.key"
        volumeMounts:
        - name: bridge-certs
          mountPath: /certs
          readOnly: true
      volumes:
      - name: bridge-certs
        secret:
          secretName: saml-oidc-bridge-tls
```

## Certificate Renewal

cert-manager automatically renews certificates before they expire.

### Monitoring Renewal

```bash
# Check certificate status
kubectl get certificate -A

# View certificate details
kubectl describe certificate saml-oidc-bridge-cert -n saml-oidc-bridge

# Check certificate expiration
kubectl get secret saml-oidc-bridge-tls -n saml-oidc-bridge -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | \
  openssl x509 -noout -dates
```

### Manual Renewal (if needed)

```bash
# Delete the secret to trigger renewal
kubectl delete secret saml-oidc-bridge-tls -n saml-oidc-bridge

# cert-manager will automatically recreate it
```

## Troubleshooting

### Certificate Not Issued

```bash
# Check certificate status
kubectl describe certificate saml-oidc-bridge-cert -n saml-oidc-bridge

# Check certificate request
kubectl get certificaterequest -n saml-oidc-bridge
kubectl describe certificaterequest <name> -n saml-oidc-bridge

# Check order (ACME)
kubectl get order -n saml-oidc-bridge
kubectl describe order <name> -n saml-oidc-bridge

# Check challenge
kubectl get challenge -n saml-oidc-bridge
kubectl describe challenge <name> -n saml-oidc-bridge
```

### Common Issues

#### 1. DNS Not Configured

**Error**: `Waiting for DNS propagation`

**Solution**: Ensure DNS A/CNAME record points to your ingress IP:

```bash
# Get ingress IP
kubectl get ingress -n saml-oidc-bridge

# Verify DNS
nslookup saml-bridge.example.com
```

#### 2. HTTP-01 Challenge Failed

**Error**: `Self check failed for domain`

**Solution**: Ensure ingress is accessible:

```bash
# Test HTTP access
curl -v http://saml-bridge.example.com/.well-known/acme-challenge/test

# Check ingress controller logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx
```

#### 3. Rate Limit Exceeded

**Error**: `too many certificates already issued`

**Solution**: Use staging issuer for testing:

```yaml
annotations:
  cert-manager.io/cluster-issuer: "letsencrypt-staging"
```

#### 4. Certificate Not Mounting

**Error**: Pod fails to start with certificate errors

**Solution**: Verify secret exists and has correct format:

```bash
# Check secret
kubectl get secret saml-oidc-bridge-tls -n saml-oidc-bridge

# Verify certificate
kubectl get secret saml-oidc-bridge-tls -n saml-oidc-bridge -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | \
  openssl x509 -text -noout
```

### Debug Mode

Enable debug logging in cert-manager:

```bash
# Edit cert-manager deployment
kubectl edit deployment cert-manager -n cert-manager

# Add to container args:
# - --v=4  # Verbose logging
```

## Best Practices

1. **Use Production Issuer**: Only use staging for testing
2. **Monitor Expiration**: Set up alerts for certificate expiration
3. **Backup Secrets**: Backup certificate secrets regularly
4. **Use ClusterIssuer**: Prefer ClusterIssuer over Issuer for reusability
5. **Set Renewal Window**: Configure `renewBefore` to allow time for troubleshooting
6. **Test First**: Always test with staging issuer before production
7. **DNS Validation**: Use DNS-01 for wildcard certificates or when HTTP-01 is not possible

## Alternative Certificate Sources

### Self-Signed Certificates (Development Only)

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: saml-oidc-bridge-selfsigned
  namespace: saml-oidc-bridge
spec:
  secretName: saml-oidc-bridge-tls
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
  commonName: saml-bridge.example.com
  dnsNames:
    - saml-bridge.example.com
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: selfsigned-issuer
  namespace: saml-oidc-bridge
spec:
  selfSigned: {}
```

### Private CA

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: private-ca
spec:
  ca:
    secretName: ca-key-pair
```

## Resources

- [cert-manager Documentation](https://cert-manager.io/docs/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [ACME Protocol](https://datatracker.ietf.org/doc/html/rfc8555)
- [Kubernetes TLS Secrets](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets)

## Support

For cert-manager issues:
- GitHub: https://github.com/cert-manager/cert-manager/issues
- Slack: https://cert-manager.io/docs/contributing/slack/

For SAML OIDC Bridge issues:
- See main [README.md](../../README.md)
- See [SECURITY.md](../SECURITY.md)
