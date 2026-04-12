.PHONY: build test test-vm test-state test-e2e lint fuzz docker clean all

BINARY=bin/bsvm
CLI_BINARY=bin/evm-cli

build:
	@mkdir -p bin
	go build -o $(BINARY) ./cmd/bsvm
	go build -o $(CLI_BINARY) ./cmd/evm-cli

test:
	go test ./pkg/... ./internal/... ./cmd/... -race -count=1 -short

test-vm:
	go test ./test/evmtest/... -run TestVMTests -timeout 30m

test-state:
	go test ./test/evmtest/... -run TestStateTests -timeout 60m

test-e2e:
	go test ./test/e2e/... -timeout 10m

test-fuzz:
	go test ./test/fuzz/... -fuzz=. -fuzztime=60s

lint:
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run ./... || go vet ./...

docker:
	docker build -t bsvm:latest .

clean:
	rm -rf bin/

all: lint test build
