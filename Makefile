build:
	go build -o ./bin/otter ./main.go

lint: ## Run the linter
	@golangci-lint run
	@go fmt ./...
	@go vet ./...