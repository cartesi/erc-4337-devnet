FOUNDRY_VERSION := 1.0.0

ORGS += eth-infinitism
ORGS += pimlico
ORGS += daimo
ORGS += zerodev
ORGS += alchemy

.PHONY: all $(ORGS)

all: $(ORGS)

install-foundry:
	foundryup --install $(FOUNDRY_VERSION)

$(ORGS):
	@$(MAKE) -C $@

zerodev: eth-infinitism daimo

alchemy: eth-infinitism
