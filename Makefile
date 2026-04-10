# Makefile for saml-oauth-proxy

.PHONY: help build test docker-build docker-push k8s-deploy k8s-delete clean

# Variables
APP_NAME := saml-oauth-proxy
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
REGISTRY ?= docker.io/yourorg
IMAGE := $(REGISTRY)/$(APP_NAME):$(VERSION)
IMAGE_LATEST := $(REGISTRY)/$(APP_NAME):latest

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the application binary
	@echo "Building $(APP_NAME)..."
	go build -o $(APP_NAME) ./cmd/$(APP_NAME)

test: ## Run tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

sqlc: ## Generate sqlc code
	@echo "Generating sqlc code..."
	sqlc generate

docker-build: ## Build Docker image
	@echo "Building Docker image $(IMAGE)..."
	docker build -t $(IMAGE) -t $(IMAGE_LATEST) .

docker-push: docker-build ## Push Docker image to registry
	@echo "Pushing Docker image..."
	docker push $(IMAGE)
	docker push $(IMAGE_LATEST)

k8s-certs: ## Generate certificates for Kubernetes
	@echo "Generating certificates..."
	@mkdir -p certs
	openssl genrsa -out certs/tls.key 2048
	openssl req -new -x509 -key certs/tls.key -out certs/tls.crt -days 365 \
		-subj "/C=US/ST=State/L=City/O=Organization/CN=saml-oauth-proxy"
	@echo "Certificates generated in certs/"

k8s-secret: k8s-certs ## Create Kubernetes TLS secret
	@echo "Creating Kubernetes secret..."
	kubectl create secret tls saml-oauth-proxy-certs \
		--cert=certs/tls.crt \
		--key=certs/tls.key \
		-n saml-oauth-proxy \
		--dry-run=client -o yaml | kubectl apply -f -

k8s-deploy: ## Deploy to Kubernetes
	@echo "Deploying to Kubernetes..."
	kubectl apply -f k8s/deployment.yaml

k8s-delete: ## Delete from Kubernetes
	@echo "Deleting from Kubernetes..."
	kubectl delete -f k8s/deployment.yaml

k8s-logs: ## Show Kubernetes logs
	kubectl logs -f -l app=saml-oauth-proxy -n saml-oauth-proxy

k8s-status: ## Show Kubernetes deployment status
	kubectl get all -n saml-oauth-proxy

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -f $(APP_NAME)
	rm -f coverage.out
	rm -rf certs/

run: build ## Build and run locally
	./$(APP_NAME) -config config.yaml -debug

dev: ## Run with hot reload (requires air: go install github.com/cosmtrek/air@latest)
	air

.DEFAULT_GOAL := help
