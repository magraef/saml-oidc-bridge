# Build stage
FROM golang:1.26-alpine AS builder

# Install build dependencies (only ca-certificates and tzdata needed, no CGO deps)
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with CGO disabled (pure Go binary)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a \
    -ldflags="-w -s" \
    -tags 'osusergo netgo sqlite_omit_load_extension' \
    -o saml-oidc-bridge \
    ./cmd/server

# Create minimal passwd file for non-root user
RUN echo "nonroot:x:65532:65532:nonroot:/:/sbin/nologin" > /tmp/passwd

# Final stage - using scratch (minimal possible image)
FROM scratch

WORKDIR /app

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy passwd file for non-root user
COPY --from=builder /tmp/passwd /etc/passwd

# Copy binary from builder
COPY --from=builder /build/saml-oidc-bridge .

# Expose port
EXPOSE 8080

# Run as non-root user (UID 65532 for OpenShift compatibility)
USER 65532:65532

ENTRYPOINT ["/app/saml-oidc-bridge"]
