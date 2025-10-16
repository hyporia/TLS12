SHELL := /bin/sh
.SILENT:

WORKDIR := shared
COVERAGE_OUT := $(WORKDIR)/coverage.out
COVERAGE_TXT := $(WORKDIR)/coverage.txt
COVERAGE_MIN ?= 80.0

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
	cd $(WORKDIR) && golangci-lint run --timeout=5m

build:
	cd $(WORKDIR) && go build ./...

test:
	cd $(WORKDIR) && go test ./... -race -coverprofile=coverage.out -covermode=atomic -count=1 && \
		go tool cover -func=coverage.out | tee coverage.txt

cover-check:
	@total=$$(awk '/^total:/ {print $$3}' $(COVERAGE_TXT) | sed 's/%//'); \
	 echo "Total coverage: $$total% (required: $(COVERAGE_MIN)%)"; \
	 awk -v t="$$total" -v m="$(COVERAGE_MIN)" 'BEGIN { exit (t + 0 >= m + 0 ? 0 : 1) }' || { \
		echo "Coverage below threshold"; exit 1; }

mod-tidy-check:
	cd $(WORKDIR) && go mod tidy && git diff --exit-code --name-only go.mod go.sum

clean:
	rm -f $(COVERAGE_OUT) $(COVERAGE_TXT)
