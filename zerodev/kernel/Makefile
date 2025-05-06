VERSIONS += 0.3.0
VERSIONS += 0.3.1
VERSIONS += 0.3.2

.PHONY: all $(VERSIONS)
all: $(VERSIONS)

$(VERSIONS):
	@$(MAKE) -C $@ -f ../../../Makefile.project
