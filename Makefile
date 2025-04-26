.PHONY: all $(ORGS)

all: $(ORGS)

$(ORGS):
	@$(MAKE) -C $@
