VERSIONS += 0.3

.PHONY: all $(VERSIONS)
all: $(VERSIONS)

$(VERSIONS):
	@$(MAKE) -C $@ -f ../../../Makefile.project
