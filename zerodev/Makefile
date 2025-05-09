PROJECTS += kernel
PROJECTS += kernel-call-policy
PROJECTS += kernel-factory-staker
PROJECTS += kernel-gas-policy
PROJECTS += kernel-sudo-policy

.PHONY: all $(PROJECTS)
all: $(PROJECTS)

$(PROJECTS):
	@$(MAKE) -C $@

kernel: kernel-factory-staker
