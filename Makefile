# SandboxSpy Makefile
BINARY_NAME=sandboxspy
SERVER_BINARY=sandboxspy-server
VERSION=$(shell git describe --tags --always --dirty)
BUILD_TIME=$(shell date +%FT%T%z)
LDFLAGS=-ldflags "-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"

.PHONY: all build clean test coverage lint install docker help

## help: Display this help message
help:
	@echo "SandboxSpy Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## all: Build everything
all: clean build-client build-server

## build-client: Build the SandboxSpy client
build-client:
	@echo "Building client..."
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-windows-amd64.exe cmd/client/main.go
	GOOS=windows GOARCH=386 go build ${LDFLAGS} -o bin/${BINARY_NAME}-windows-386.exe cmd/client/main.go
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-linux-amd64 cmd/client/main.go
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-darwin-amd64 cmd/client/main.go
	@echo "Client binaries built successfully"

## build-server: Build the SandboxSpy server
build-server:
	@echo "Building server..."
	go build ${LDFLAGS} -o bin/${SERVER_BINARY} cmd/server/main.go
	@echo "Server binary built successfully"

## build-docker: Build Docker images
build-docker:
	docker build -f deployments/docker/Dockerfile.client -t sandboxspy/client:${VERSION} .
	docker build -f deployments/docker/Dockerfile.server -t sandboxspy/server:${VERSION} .
	@echo "Docker images built successfully"

## test: Run tests
test:
	@echo "Running tests..."
	go test -v -race -timeout 30s ./...

## coverage: Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## lint: Run linters
lint:
	@echo "Running linters..."
	golangci-lint run ./...
	@echo "Linting completed"

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	@echo "Clean completed"

## install-deps: Install dependencies
install-deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy
	@echo "Dependencies installed"

## install-tools: Install development tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	@echo "Tools installed"

## run-server: Run the server locally
run-server:
	@echo "Starting server..."
	go run cmd/server/main.go

## run-client: Run the client locally
run-client:
	@echo "Starting client..."
	go run cmd/client/main.go

## docker-compose-up: Start services with docker-compose
docker-compose-up:
	docker-compose -f deployments/docker/docker-compose.yml up -d

## docker-compose-down: Stop services
docker-compose-down:
	docker-compose -f deployments/docker/docker-compose.yml down

## migrate-up: Run database migrations up
migrate-up:
	migrate -path migrations -database "sqlite3://sandboxspy.db" up

## migrate-down: Run database migrations down
migrate-down:
	migrate -path migrations -database "sqlite3://sandboxspy.db" down

## gen-docs: Generate API documentation
gen-docs:
	swag init -g cmd/server/main.go -o docs/

## release: Create a new release
release: clean test build-client build-server
	@echo "Creating release ${VERSION}..."
	mkdir -p releases/${VERSION}
	cp -r bin/* releases/${VERSION}/
	cp README.md releases/${VERSION}/
	cp LICENSE releases/${VERSION}/
	tar -czf releases/sandboxspy-${VERSION}.tar.gz -C releases/${VERSION} .
	@echo "Release ${VERSION} created"