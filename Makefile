SHELL := /bin/sh
.SILENT:

WORKDIR := ./
COVERAGE_OUT := $(WORKDIR)/coverage.out
COVERAGE_TXT := $(WORKDIR)/coverage.txt
COVERAGE_MIN ?= 60.0

.PHONY: all quality fmt vet lint build test cover-check mod-tidy-check clean

all: quality

quality: fmt build vet lint test cover-check mod-tidy-check

fmt:
	cd $(WORKDIR) && \
	out=$$(gofmt -s -l .); \
	if [ -n "$$out" ]; then \
		echo "Go files not formatted:"; echo "$$out"; \
		exit 1; \
	fi

vet:
	cd $(WORKDIR) && go vet ./...

lint:
	golangci-lint run ./... --timeout=5m --config=.golangci.yml

build:
	cd $(WORKDIR) && go build ./...

test:
	cd $(WORKDIR) && go test ./... -race -coverprofile=coverage.out -covermode=atomic -count=1

mod-tidy-check:
	cd $(WORKDIR) && \
	go mod tidy && \
	changed=0; \
	if ! git diff --quiet -- go.mod; then changed=1; fi; \
	if [ -e go.sum ]; then \
		if ! git ls-files --error-unmatch go.sum >/dev/null 2>&1; then changed=1; fi; \
		if ! git diff --quiet -- go.sum; then changed=1; fi; \
	fi; \
	if [ "$$changed" -ne 0 ]; then \
		echo "go.mod/go.sum are not tidy. Run 'go mod tidy'."; \
		exit 1; \
	fi

clean:
	rm -f $(COVERAGE_OUT) $(COVERAGE_TXT)
