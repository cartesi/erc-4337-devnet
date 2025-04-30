VERSIONS += 2.0.0

.PHONY: all $(VERSIONS)
all: $(VERSIONS)

$(VERSIONS):
	@$(MAKE) -C $@ -f ../../../Makefile.project
