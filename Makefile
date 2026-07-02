YAEGI_VERSION ?= v0.16.1
GOVULNCHECK_VERSION ?= v1.3.0

.PHONY: fmt tidy vet lint test vulncheck vendor yaegi-test ci ci-full clean

fmt:
	gofmt -w .

tidy:
	go mod tidy

vet:
	go vet ./...

lint:
	golangci-lint run

test:
	go test -race -cover ./...

vulncheck:
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	govulncheck ./...

vendor:
	go mod vendor

# Yaegi compatibility check. Vendors dependencies first so Yaegi can resolve
# local sub-packages (e.g. github.com/fosrl/badger/ips) without needing a
# plugins-local copy layout. Must be run from a GOPATH-compatible directory
# (go/src/github.com/fosrl/badger) for local sub-package resolution.
yaegi-test: vendor
	go run github.com/traefik/yaegi/cmd/yaegi@$(YAEGI_VERSION) test -v .

# Reproduce the CI checks locally (excluding yaegi and lint).
ci:
	test -z "$$(gofmt -l .)"
	go mod tidy
	git diff --exit-code -- go.mod go.sum
	go vet ./...
	go test -race -cover ./...
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	govulncheck ./...

# Full CI including lint and yaegi compatibility check.
ci-full: ci
	$(MAKE) lint
	$(MAKE) yaegi-test

clean:
	rm -rf vendor
