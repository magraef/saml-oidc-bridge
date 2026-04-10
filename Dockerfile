# Build stage
FROM golang:1.26-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev sqlite-dev

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with static linking
RUN CGO_ENABLED=1 GOOS=linux go build \
    -a \
    -ldflags="-w -s -extldflags '-static'" \
    -tags 'osusergo netgo sqlite_omit_load_extension' \
    -o saml-oidc-bridge \
    ./cmd/server

# Final stage - using distroless static (minimal, no shell, includes ca-certs)
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/saml-oidc-bridge .

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Expose port
EXPOSE 8080

# Run as non-root user (distroless nonroot user is 65532)
USER nonroot:nonroot

ENTRYPOINT ["/app/saml-oidc-bridge"]