FOUNDRY_VERSION := 1.0.0

ORGS += eth-infinitism
ORGS += pimlico

.PHONY: all $(ORGS)

all: $(ORGS)

install-foundry:
	foundryup --install $(FOUNDRY_VERSION)

$(ORGS):
	@$(MAKE) -C $@
