
BINARY?=portik
# Version/commit -- can be set when invoking make, or computed from git
VERSION?=dev
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "")
LDFLAGS?=-X 'github.com/pratik-anurag/portik/internal/cli.version=$(VERSION)' -X 'github.com/pratik-anurag/portik/internal/cli.commit=$(COMMIT)'

.PHONY: build test run clean release-snapshot release

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) .

test:
	go test ./...

run:
	go run . --help

clean:
	rm -rf bin dist

release-snapshot:
	goreleaser release --snapshot --skip-publish --clean

release:
	goreleaser release --clean
