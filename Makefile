BINARY := seki
VERSION := 0.1.0-dev

.PHONY: build build-cli test clean run

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/seki

build-cli:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/seki-cli ./cmd/seki-cli

test:
	go test ./...

clean:
	rm -rf bin/

run: build
	./bin/$(BINARY)
