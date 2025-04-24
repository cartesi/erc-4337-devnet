VERSIONS += 0.6
VERSIONS += 0.7
VERSIONS += 0.8

.PHONY: all $(VERSIONS)
all: $(VERSIONS)

$(VERSIONS):
	@$(MAKE) -C $@ -f ../../../Makefile.project
