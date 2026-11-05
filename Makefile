.PHONY: all build test race vet fmt demo demo-test demo-scan demo-graph demo-chaos demo-gateway clean

BIN := bin
AUDIT := $(BIN)/chaos-audit.jsonl

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

demo: demo-test demo-scan

# groot test on the demo suite (exits 1: three scenarios fail by design).
demo-test: build
	-./$(BIN)/groot test --suite examples/demo-env/groot-suite.json --out $(BIN)/test-run

# Blast-radius scan of the demo environment (exits 1: it has critical findings).
demo-scan: build
	-./$(BIN)/groot scan examples/demo-env

demo-graph: build
	./$(BIN)/groot graph examples/demo-env

# A naive agent talks to the fake MCP server through the gateway with chaos
# on; the analyzer then reports the retry storm, duplicate email and escalation.
demo-chaos: build
	@rm -f $(AUDIT)
	./$(BIN)/naive-agent -- ./$(BIN)/groot gateway stdio \
		--policy examples/demo-env/gateway/chaos-policy.json --agent support-bot --audit $(AUDIT) \
		-- ./$(BIN)/fake-mcp-server --poison
	-./$(BIN)/groot analyze $(AUDIT)

# Gateway in front of the fake server over HTTP, with the enforcing policy.
demo-gateway: build
	./$(BIN)/fake-mcp-server --http 127.0.0.1:9000 & \
	./$(BIN)/groot gateway http --policy examples/demo-env/gateway/policy.json \
		--upstream http://127.0.0.1:9000/mcp --agent support-bot --audit -

clean:
	rm -rf $(BIN)
