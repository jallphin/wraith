BINARY   := wraith
CMD      := ./cmd/wraith
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS  := -ldflags "-X main.GitCommit=$(COMMIT)"

.PHONY: build install clean version

build:
	go build $(LDFLAGS) -o $(BINARY) $(CMD)

install:
	go install $(LDFLAGS) $(CMD)

clean:
	rm -f $(BINARY)

version:
	@./$(BINARY) version 2>/dev/null || echo "run 'make build' first"
