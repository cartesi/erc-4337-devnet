VERSIONS += 1.1.0

.PHONY: all $(VERSIONS)
all: $(VERSIONS)

$(VERSIONS):
	@$(MAKE) -C $@ -f ../../../Makefile.project
