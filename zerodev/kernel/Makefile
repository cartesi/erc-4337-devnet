VERSIONS += 3.0
VERSIONS += 3.1
VERSIONS += 3.2

.PHONY: all $(VERSIONS)
all: $(VERSIONS)

$(VERSIONS):
	@$(MAKE) -C $@ -f ../../../Makefile.project
