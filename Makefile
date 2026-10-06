.PHONY: build test vet fmt lint run-demo tidy

build:
	go build ./...

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

lint:
	golangci-lint run ./... || true

run-demo:
	go run ./tools/demoserver --mode vulnerable
