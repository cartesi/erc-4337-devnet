PROJECTS += kernel
PROJECTS += kernel-factory-staker
PROJECTS += kernel-sudo-policy

.PHONY: all $(PROJECTS)
all: $(PROJECTS)

$(PROJECTS):
	@$(MAKE) -C $@

kernel: kernel-factory-staker
