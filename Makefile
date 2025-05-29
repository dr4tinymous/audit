.PHONY: all check test lint staticcheck race cover bench build clean

RESULTS_FILE := results.txt
PKG_NAME := $(notdir $(CURDIR))

all: check build

check: test lint staticcheck race cover
	@echo "✅ All checks passed. Ready to build." >> $(RESULTS_FILE)

test:
	@echo "=== Running go test ===" > $(RESULTS_FILE)
	@go test ./... -v >> $(RESULTS_FILE) 2>&1

lint:
	@echo "=== Running golangci-lint ===" >> $(RESULTS_FILE)
	@golangci-lint run ./... >> $(RESULTS_FILE) 2>&1

staticcheck:
	@echo "=== Running staticcheck ===" >> $(RESULTS_FILE)
	@staticcheck ./... >> $(RESULTS_FILE) 2>&1

race:
	@echo "=== Running tests with race detector ===" >> $(RESULTS_FILE)
	@go test -race ./... >> $(RESULTS_FILE) 2>&1

cover:
	@echo "=== Running coverage ===" >> $(RESULTS_FILE)
	@go test ./... -coverprofile=coverage.out >> $(RESULTS_FILE) 2>&1
	@go tool cover -func=coverage.out | tee -a $(RESULTS_FILE)

bench:
	@echo "=== Running benchmarks ===" >> $(RESULTS_FILE)
	@go test -bench=. -benchmem ./... >> $(RESULTS_FILE) 2>&1

build:
	@echo "=== Building binary $(PKG_NAME) ===" >> $(RESULTS_FILE)
	@go build -o $(PKG_NAME)

clean:
	@rm -f $(PKG_NAME) $(RESULTS_FILE) coverage.out
