PROJECTS += entrypoint
PROJECTS += simple-account

.PHONY: all $(PROJECTS)
all: $(PROJECTS)

$(PROJECTS):
	@$(MAKE) -C $@

simple-account: entrypoint
