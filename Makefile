.PHONY: all build test race vet fmt demo demo-test demo-compound demo-scan clean

BIN := bin

all: fmt vet test build

build:
	go build -o $(BIN)/ ./cmd/... ./examples/...

test:
	go test ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run: gofmt -w ." && exit 1)

demo: demo-test demo-compound demo-scan

# groot test on the demo suite, with an HTML report (exits 1: three scenarios fail by design).
demo-test: build
	-./$(BIN)/groot test --suite examples/demo-env/groot-suite.json --out $(BIN)/test-run --html $(BIN)/report.html

# Attacks while tools are failing, each with a control run (exits 1 by design).
demo-compound: build
	-./$(BIN)/groot test --suite examples/demo-env/groot-suite-compound.json --out $(BIN)/test-compound --html $(BIN)/report-compound.html

# What the demo agents can reach (exits 1: it has critical findings), plus the HTML reach report.
demo-scan: build
	-./$(BIN)/groot scan examples/demo-env
	./$(BIN)/groot graph examples/demo-env > $(BIN)/reach.html
	@echo "reports: $(BIN)/report.html $(BIN)/report-compound.html $(BIN)/reach.html"

clean:
	rm -rf $(BIN)
