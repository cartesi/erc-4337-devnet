BUILD_TARGETS   := $(addprefix build-,   $(VERSIONS))
DEPLOY_TARGETS  := $(addprefix deploy-,  $(VERSIONS))

.PHONY: build deploy $(VERSIONS) $(BUILD_TARGETS) $(DEPLOY_TARGETS)

build:  $(BUILD_TARGETS)
deploy: $(DEPLOY_TARGETS)

$(BUILD_TARGETS):   build-%:
	@$(MAKE) -C $* -f ../../../internal/Makefile.project build

$(DEPLOY_TARGETS):  deploy-%:
	@$(MAKE) -C $* -f ../../../internal/Makefile.project deploy
