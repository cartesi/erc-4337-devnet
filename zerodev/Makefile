PROJECTS += kernel-factory-staker
PROJECTS += kernel

.PHONY: all $(PROJECTS)
all: $(PROJECTS)

$(PROJECTS):
	@$(MAKE) -C $@

kernel: kernel-factory-staker
