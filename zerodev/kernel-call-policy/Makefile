VERSIONS += 0.0.1
VERSIONS += 0.0.2
VERSIONS += 0.0.3
VERSIONS += 0.0.4

.PHONY: all $(VERSIONS)
all: $(VERSIONS)

$(VERSIONS):
	@$(MAKE) -C $@ -f ../../../Makefile.project
