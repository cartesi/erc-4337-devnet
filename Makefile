FOUNDRY_VERSION := 1.4.3

SVM_VERSION := 0.5.19

SOLC_VERSIONS += 0.8.15
SOLC_VERSIONS += 0.8.17
SOLC_VERSIONS += 0.8.21
SOLC_VERSIONS += 0.8.23
SOLC_VERSIONS += 0.8.24
SOLC_VERSIONS += 0.8.25
SOLC_VERSIONS += 0.8.26
SOLC_VERSIONS += 0.8.28

ORGS += eth-infinitism
ORGS += pimlico
ORGS += daimo
ORGS += zerodev
ORGS += alchemy

BUILD_TARGETS  := $(addprefix build-,  $(ORGS))
DEPLOY_TARGETS := $(addprefix deploy-, $(ORGS))

.PHONY: $(BUILD_TARGETS)
.PHONY: $(DEPLOY_TARGETS)
.PHONY: build
.PHONY: check-foundry
.PHONY: check-foundry-version
.PHONY: check-jq
.PHONY: check-svm
.PHONY: check-svm-version
.PHONY: deploy
.PHONY: help
.PHONY: install-foundry
.PHONY: install-solc
.PHONY: install-svm

help:
	@echo "ERC-4337 devnet -- Account Abstraction contracts for local development"
	@echo
	@echo "Usage"
	@echo "-----"
	@echo "  make <target>"
	@echo
	@echo "Targets"
	@echo "-------"
	@echo "  build                  Build all contracts (requires forge)"
	@echo "  check-foundry          Check whether Foundry is installed"
	@echo "  check-foundry-version  Check whether Foundry $(FOUNDRY_VERSION) is installed"
	@echo "  check-jq               Check whether jq is installed"
	@echo "  check-svm              Check whether svm is installed"
	@echo "  check-svm-version      Check whether svm $(SVM_VERSION) is installed"
	@echo "  deploy                 Deploy all contracts to Anvil (requires forge and jq)"
	@echo "  help                   Display this help message"
	@echo "  install-foundry        Install Foundry $(FOUNDRY_VERSION) (requires foundryup)"
	@echo "  install-solc           Install all versions of the Solidity compiler used (requires svm)"
	@echo "  install-svm            Install SVM $(SVM_VERSION) (requires cargo)"

check-foundry:
	@(command -v forge > /dev/null) || (echo "Foundry is not installed." && exit 1)

check-foundry-version: check-foundry
	@(forge --version | diff --color -u internal/forge-version -) || \
		(echo "Foundry $(FOUNDRY_VERSION) is not installed." && exit 1)

check-svm:
	@(command -v svm > /dev/null) || (echo "svm is not installed." && exit 1)

check-svm-version: check-svm
	@(svm --version | \
		sed -E 's/[ ]*\(VERGEN_IDEMPOTENT_OUTPUT [0-9]{4}-[0-9]{2}-[0-9]{2}\)//' | \
		diff --color -u internal/svm-version -) || \
		(echo "svm $(SVM_VERSION) is not installed." && exit 1)

check-jq:
	@(command -v jq > /dev/null) || (echo "jq is not installed." && exit 1)

install-foundry:
	@foundryup --install $(FOUNDRY_VERSION)

install-svm:
	@cargo install svm-rs --version $(SVM_VERSION)

install-solc: check-svm-version
	@svm install --non-interactive $(SOLC_VERSIONS)

build:   $(BUILD_TARGETS)
deploy:  $(DEPLOY_TARGETS)

$(BUILD_TARGETS): build-%: check-foundry-version
	@$(MAKE) -C $* build

$(DEPLOY_TARGETS): deploy-%: check-foundry-version check-jq
	@$(MAKE) -C $* deploy

deploy-zerodev: deploy-eth-infinitism deploy-daimo

deploy-alchemy: deploy-eth-infinitism
