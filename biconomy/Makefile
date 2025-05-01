PROJECTS += mee
PROJECTS += nexus

.PHONY: all $(PROJECTS)
all: $(PROJECTS)

$(PROJECTS):
	@$(MAKE) -C $@

nexus: mee
