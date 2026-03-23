BINARY := seki
VERSION := 0.1.0-dev

.PHONY: build test clean run

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/seki

test:
	go test ./...

clean:
	rm -rf bin/

run: build
	./bin/$(BINARY)
