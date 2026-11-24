.PHONY: build vet lint test ci

build:
	go build ./...

vet:
	go vet ./...

lint:
	golangci-lint run --timeout 5m

test:
	go test -race -timeout 60s ./...

ci: build vet lint test
