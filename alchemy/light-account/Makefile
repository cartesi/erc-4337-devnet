FOUNDRY_VERSION := 1.0.0
VERSIONS += 1.1.0
VERSIONS += 2.0.0

.PHONY: all $(VERSIONS)
all: $(VERSIONS)

$(VERSIONS):
	@$(MAKE) -C $@ -f ../../../Makefile.project

2.0.0:
	$(MAKE) -f ../../Makefile install-foundry FOUNDRY_VERSION=0.3.0
	$(MAKE) -C $@ -f ../../../Makefile.project
	$(MAKE) -f ../../Makefile install-foundry
