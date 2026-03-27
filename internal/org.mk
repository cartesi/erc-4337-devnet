BUILD_TARGETS   := $(addprefix build-,   $(PROJECTS))
DEPLOY_TARGETS  := $(addprefix deploy-,  $(PROJECTS))

.PHONY: build deploy $(PROJECTS) $(BUILD_TARGETS) $(DEPLOY_TARGETS)

build:  $(BUILD_TARGETS)
deploy: $(DEPLOY_TARGETS)

$(BUILD_TARGETS):   build-%:
	@$(MAKE) -C $* build

$(DEPLOY_TARGETS):  deploy-%:
	@$(MAKE) -C $* deploy
