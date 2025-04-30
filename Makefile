FOUNDRY_VERSION := 1.0.0

.PHONY: all $(ORGS)

all: $(ORGS)

install-foundry:
	foundryup --install $(FOUNDRY_VERSION)

$(ORGS):
	@$(MAKE) -C $@
