IMPLEMENTATION ?= aggregator-provision
VERSION ?= 0.1.0
GO_TEST_JSON ?= conformance/go-test.json
CONFORMANCE_RESULTS ?= conformance/results.json
CONFORMANCE_CLI ?= node ../aggregator-conformance/src/cli/main.js
export GOCACHE ?= $(CURDIR)/.cache/go-build

.PHONY: test
test:
	go tool gotestsum --format testname --jsonfile $(GO_TEST_JSON) -- ./...

.PHONY: conformance-results
conformance-results:
	@$(CONFORMANCE_CLI) --help >/dev/null 2>&1 || { \
		echo "aggregator-conformance CLI is required. Set CONFORMANCE_CLI or install aggregator-conformance on PATH." >&2; \
		exit 127; \
	}
	$(CONFORMANCE_CLI) convert go-test \
		--input $(GO_TEST_JSON) \
		--implementation $(IMPLEMENTATION) \
		--version $(VERSION) \
		--output $(CONFORMANCE_RESULTS)

.PHONY: conformance-check
conformance-check: test conformance-results
	$(CONFORMANCE_CLI) check \
		--deployment conformance/deployment.yml \
		--coverage conformance/coverage.yml \
		--results $(CONFORMANCE_RESULTS)

.PHONY: conformance-plan
conformance-plan:
	@$(CONFORMANCE_CLI) --help >/dev/null 2>&1 || { \
		echo "aggregator-conformance CLI is required. Set CONFORMANCE_CLI or install aggregator-conformance on PATH." >&2; \
		exit 127; \
	}
	$(CONFORMANCE_CLI) plan \
		--deployment conformance/deployment.yml \
		--report json
