
.PHONY: run
run:
	go run ./cmd/keysafe

# Build the binary
.PHONY: build
build: 
	go build -o ./bin/keysafe ./cmd/keysafe


# Run the unit tests
.PHONY: test
test: ## Run the unit tests
	go test ./... -v	

