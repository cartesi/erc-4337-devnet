PROJECTS += kernel
PROJECTS += kernel-call-policy
PROJECTS += kernel-ecdsa-signer
PROJECTS += kernel-factory-staker
PROJECTS += kernel-gas-policy
PROJECTS += kernel-rate-limit-policy
PROJECTS += kernel-signature-policy
PROJECTS += kernel-sudo-policy
PROJECTS += kernel-timestamp-policy

.PHONY: all $(PROJECTS)
all: $(PROJECTS)

$(PROJECTS):
	@$(MAKE) -C $@

kernel: kernel-factory-staker
