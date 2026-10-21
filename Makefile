BINARY := sentryhive

.PHONY: build run test fmt vet docker clean

build:
	go build -o bin/$(BINARY) ./cmd/sentryhive

run: build
	./bin/$(BINARY) -config config.yaml

test:
	go test ./...

fmt:
	gofmt -l -w .

vet:
	go vet ./...

docker:
	docker build -t sentryhive:latest .

clean:
	rm -rf bin/ data/
