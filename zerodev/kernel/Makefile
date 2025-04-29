VERSIONS += 3.0

.PHONY: all $(VERSIONS)
all: $(VERSIONS)

$(VERSIONS):
	@$(MAKE) -C $@ -f ../../../Makefile.project
