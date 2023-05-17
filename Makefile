# VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the VERSION as arg of the bundle target (e.g make bundle VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export VERSION=0.0.2)
VERSION ?= 0.0.0-dev

GO_VERSION = $(shell cat .go-version)

CONFIG_SRC_DIR ?= config
CONFIG_BUILD_DIR ?= build/config
CONFIG_MANAGER_DIR ?= $(CONFIG_BUILD_DIR)/manager
KUSTOMIZATION ?= default
KUSTOMIZE_BUILD_DIR ?= $(CONFIG_BUILD_DIR)/$(KUSTOMIZATION)

VAULT_IMAGE_TAG ?= latest
VAULT_IMAGE_REPO ?=
K8S_VAULT_NAMESPACE ?= vault
KIND_K8S_VERSION ?= v1.25.3
VAULT_HELM_VERSION ?= 0.23.0
# Root directory to export kind cluster logs after each test run.
EXPORT_KIND_LOGS_ROOT ?=

TERRAFORM_VERSION ?= 1.3.7
GOFUMPT_VERSION ?= v0.4.0
HELMIFY_VERSION ?= v0.3.22
COPYWRITE_VERSION ?= 0.16.3

TESTCOUNT ?= 1
TESTARGS ?= -test.v -count=$(TESTCOUNT)

# Run integration tests against a Helm installed Operator
TEST_WITH_HELM ?=

# Suppress the output from terraform when running the integration tests.
SUPPRESS_TF_OUTPUT ?=
# Skip the integration test cleanup.
SKIP_CLEANUP ?=
# The number of k8s secrets to create in the VaultDynamicSecret's integration tests.
K8S_DB_SECRET_COUNT ?=


# CHANNELS define the bundle channels used in the bundle.
# Add a new line here if you would like to change its default config. (E.g CHANNELS = "candidate,fast,stable")
# To re-generate a bundle for other specific channels without changing the standard setup, you can:
# - use the CHANNELS as arg of the bundle target (e.g make bundle CHANNELS=candidate,fast,stable)
# - use environment variables to overwrite this value (e.g export CHANNELS="candidate,fast,stable")
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif

# DEFAULT_CHANNEL defines the default channel used in the bundle.
# Add a new line here if you would like to change its default config. (E.g DEFAULT_CHANNEL = "stable")
# To re-generate a bundle for any other default channel without changing the default setup, you can:
# - use the DEFAULT_CHANNEL as arg of the bundle target (e.g make bundle DEFAULT_CHANNEL=stable)
# - use environment variables to overwrite this value (e.g export DEFAULT_CHANNEL="stable")
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# IMAGE_TAG_BASE defines the docker.io namespace and part of the image name for remote images.
# This variable is used to construct full image tags for bundle and catalog images.
#
# For example, running 'make bundle-build bundle-push catalog-build catalog-push' will build and push both
# hashicorp.com/vault-secrets-operator-bundle:$VERSION and hashicorp.com/vault-secrets-operator-catalog:$VERSION.
IMAGE_TAG_BASE ?= hashicorp/vault-secrets-operator

# BUNDLE_IMG defines the image:tag used for the bundle.
# You can use it as an arg. (E.g make bundle-build BUNDLE_IMG=<some-registry>/<project-name-bundle>:<tag>)
BUNDLE_IMG ?= $(IMAGE_TAG_BASE)-bundle:v$(VERSION)

# BUNDLE_GEN_FLAGS are the flags passed to the operator-sdk generate bundle command
BUNDLE_GEN_FLAGS ?= -q --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)

# USE_IMAGE_DIGESTS defines if images are resolved via tags or digests
# You can enable this value if you would like to use SHA Based Digests
# To enable set flag to true
USE_IMAGE_DIGESTS ?= false
ifeq ($(USE_IMAGE_DIGESTS), true)
	BUNDLE_GEN_FLAGS += --use-image-digests
endif

# Image URL to use all building/pushing image targets
IMG ?= $(IMAGE_TAG_BASE):$(VERSION)

# Default path to saving and loading the Docker image for IMG.
IMAGE_ARCHIVE_FILE ?= $(BUILD_DIR)/$(subst /,_,$(IMAGE_TAG_BASE))-$(VERSION).tar

# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.24.1

# Kind cluster name
KIND_CLUSTER_NAME ?= vault-secrets-operator
# Kind cluster context
KIND_CLUSTER_CONTEXT ?= kind-$(KIND_CLUSTER_NAME)
# Kind config file
KIND_CONFIG_FILE ?= $(INTEGRATION_TEST_ROOT)/kind/config.yaml

# Operator namespace as configured in $(KUSTOMIZE_BUILD_DIR)/kustomization.yaml
OPERATOR_NAMESPACE ?= vault-secrets-operator-system

# Run tests against Vault enterprise when true.
VAULT_ENTERPRISE ?= false
# The vault license.
_VAULT_LICENSE ?=

# root directory for all integration tests
INTEGRATION_TEST_ROOT = ./test/integration

# directory containing Kubernetes patches to be applied after Vault is been brought up in K8s.
VAULT_PATCH_ROOT = $(INTEGRATION_TEST_ROOT)/vault

TF_INFRA_SRC_DIR ?= $(INTEGRATION_TEST_ROOT)/infra
TF_VAULT_STATE_DIR ?= $(TF_INFRA_SRC_DIR)/state

# directory for eks infrastructure for running tests
TF_EKS_DIR ?= $(INTEGRATION_TEST_ROOT)/infra/eks

BUILD_DIR = dist
BIN_NAME = vault-secrets-operator
GOOS ?= linux
GOARCH ?= amd64

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: copywrite controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	@$(COPYWRITE) headers &> /dev/null

.PHONY: generate
generate: copywrite controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	@$(COPYWRITE) headers &> /dev/null

.PHONY: fmt
fmt: gofumpt ## Run gofumpt against code.
	$(GOFUMPT) -l -w -extra .

.PHONY: check-fmt
check-fmt: gofumpt go-version-check ## Check formatting
	@sh -c $(CURDIR)/scripts/goversioncheck.sh
	@GOFUMPT_BIN=$(GOFUMPT) $(CURDIR)/scripts/gofmtcheck.sh $(CURDIR)

.PHONY: go-version-check
go-version-check: ## Check formatting
	@sh -c $(CURDIR)/scripts/goversioncheck.sh

.PHONY: tffmt
fmttf: terraform ## Run gofumpt against code.
	$(TERRAFORM) fmt -recursive -write=true

.PHONY: check-tffmt
check-tffmt: terraform ## Check formatting
	@TERRAFORM_BIN=$(TERRAFORM) $(CURDIR)/scripts/tffmtcheck.sh $(CURDIR)

.PHONY: vet
vet: go-version-check ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" go test ./... $(TESTARGS) -coverprofile cover.out

##@ Build

.PHONY: build
build: generate fmt vet ## Build manager binary.
	go build \
    	-ldflags "${LD_FLAGS} $(shell ./scripts/ldflags-version.sh)" \
		-o bin/vault-secrets-operator main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./main.go

.PHONY: docker-build
docker-build: test ## Build docker image with the manager.
	docker build -t $(IMG) . --target=dev \
	--build-arg GOOS=$(GOOS) \
	--build-arg GOARCH=$(GOARCH) \
	--build-arg GO_VERSION=$(shell cat .go-version) \
	--build-arg LD_FLAGS="$(shell GOOS=$(GOOS) GOARCH=$(GOARCH) ./scripts/ldflags-version.sh)"

.PHONY: docker-image-save
docker-image-save: ##
	docker image save --output $(IMAGE_ARCHIVE_FILE) $(IMG)

.PHONY: docker-image-load
docker-image-load:  ##
	docker image load --input $(IMAGE_ARCHIVE_FILE)

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push $(IMG)

##@ CI

.PHONY: ci-build
ci-build: ## Build operator binary (without generating assets).
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-ldflags "${LD_FLAGS} $(shell GOOS=$(GOOS) GOARCH=$(GOARCH) ./scripts/ldflags-version.sh)" \
		-a \
		-o $(BUILD_DIR)/$(BIN_NAME) \
		.

# TODO: this does not work on arm64 build machines.
.PHONY: ci-docker-build
ci-docker-build: ## Build docker image with the operator (without generating assets)
	mkdir -p $(BUILD_DIR)/$(GOOS)/$(GOARCH)
	cp $(BUILD_DIR)/$(BIN_NAME) $(BUILD_DIR)/$(GOOS)/$(GOARCH)/$(BIN_NAME)
	docker build -t $(IMG) . --target release-default --build-arg GO_VERSION=$(shell cat .go-version)

.PHONY: ci-test
ci-test: vet envtest ## Run tests in CI (without generating assets)
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" go test ./... $(TESTARGS) -coverprofile cover.out

.PHONY: copy-config
copy-config: ## Copy kustomize config to CONFIG_BUILD_DIR
	@rm -rf $(CONFIG_BUILD_DIR)
	@mkdir -p $(dir $(CONFIG_BUILD_DIR))
	@cp -a $(CONFIG_SRC_DIR) $(CONFIG_BUILD_DIR)

.PHONY: set-image
set-image: kustomize copy-config ## Set the controller image in CONFIG_MANAGER_DIR
	cd $(CONFIG_MANAGER_DIR) && $(KUSTOMIZE) edit set image controller=$(IMG)

.PHONY: set-image integration-test
integration-test: set-image setup-vault ## Run integration tests for Vault OSS
	SUPPRESS_TF_OUTPUT=$(SUPPRESS_TF_OUTPUT) SKIP_CLEANUP=$(SKIP_CLEANUP) OPERATOR_NAMESPACE=$(OPERATOR_NAMESPACE) \
	OPERATOR_IMAGE_REPO=$(IMAGE_TAG_BASE) OPERATOR_IMAGE_TAG=$(VERSION) \
    INTEGRATION_TESTS=true KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) KIND_CLUSTER_CONTEXT=$(KIND_CLUSTER_CONTEXT) CGO_ENABLED=0 \
	go test github.com/hashicorp/vault-secrets-operator/test/integration/... $(TESTARGS) -timeout=30m

.PHONY: integration-test-helm
integration-test-helm: setup-integration-test ## Run integration tests for Vault OSS
	$(MAKE) integration-test TEST_WITH_HELM=true

.PHONY: integration-test-helm-ent
integration-test-helm-ent: ## Run integration tests for Vault Enterprise
	$(MAKE) integration-test TEST_WITH_HELM=true VAULT_ENTERPRISE=true ENT_TESTS=$(VAULT_ENTERPRISE)

.PHONY: integration-test-ent
integration-test-ent: ## Run integration tests for Vault Enterprise
	$(MAKE) integration-test VAULT_ENTERPRISE=true ENT_TESTS=$(VAULT_ENTERPRISE)

.PHONY: integration-test-both
integration-test-both: ## Run integration tests against Vault Enterprise and Vault OSS
	$(MAKE) integration-test VAULT_ENTERPRISE=true ENT_TESTS=$(VAULT_ENTERPRISE)
	$(MAKE) integration-test

.PHONY: setup-kind
setup-kind: ## create a kind cluster for running the acceptance tests locally
	kind get clusters | grep --silent "^$(KIND_CLUSTER_NAME)$$" || \
	kind create cluster \
		--wait=5m \
		--image kindest/node:$(KIND_K8S_VERSION) \
		--name $(KIND_CLUSTER_NAME)  \
		--config $(KIND_CONFIG_FILE)
	kubectl config use-context $(KIND_CLUSTER_CONTEXT)

.PHONY: delete-kind
delete-kind: ## delete the kind cluster
	kind delete cluster --name $(KIND_CLUSTER_NAME) || true
	find $(INTEGRATION_TEST_ROOT)/infra -type f -name '*tfstate*' | xargs rm &> /dev/null || true

.PHONY: setup-integration-test
## Create Vault inside the cluster
setup-integration-test: setup-vault ## Deploy Vault Enterprise for integration testing

.PHONY: setup-vault
setup-vault: terraform kustomize set-vault-license ## Deploy Vault for integration testing
	@mkdir -p $(TF_VAULT_STATE_DIR)
ifeq ($(VAULT_ENTERPRISE), true)
    ## ensure that the license is *not* emitted to the console
	@echo "vault_license = \"$(_VAULT_LICENSE)\"" > $(TF_VAULT_STATE_DIR)/license.auto.tfvars
ifdef VAULT_IMAGE_REPO
	$(eval EXTRA_VARS=-var vault_image_repo_ent=$(VAULT_IMAGE_REPO))
endif
else ifdef VAULT_IMAGE_REPO
	$(eval EXTRA_VARS=-var vault_image_repo=$(VAULT_IMAGE_REPO))
endif
	@rm -f $(TF_VAULT_STATE_DIR)/*.tf
	cp -v $(TF_INFRA_SRC_DIR)/*.tf $(TF_VAULT_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_VAULT_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_VAULT_STATE_DIR) apply -auto-approve \
		-var vault_enterprise=$(VAULT_ENTERPRISE) \
		-var vault_image_tag=$(VAULT_IMAGE_TAG) \
		-var k8s_namespace=$(K8S_VAULT_NAMESPACE) \
		-var k8s_config_context=$(KIND_CLUSTER_CONTEXT) \
		$(EXTRA_VARS) || exit 1 \
	rm -f $(TF_VAULT_STATE_DIR)/*.tfvars
	K8S_VAULT_NAMESPACE=$(K8S_VAULT_NAMESPACE) $(VAULT_PATCH_ROOT)/patch-vault.sh

.PHONY: setup-integration-test-ent
## Create Vault inside the cluster
setup-integration-test-ent: setup-vault-ent ## Deploy Vault Enterprise for integration testing

.PHONY: setup-vault-ent
## Create Vault inside the cluster
setup-vault-ent: ## Deploy Vault Enterprise for integration testing
	$(MAKE) setup-vault VAULT_ENTERPRISE=true

.PHONY: set-vault-license
set-vault-license:
ifeq ($(VAULT_ENTERPRISE), true)
ifdef VAULT_LICENSE_CI
	@echo Getting license from VAULT_LICENSE_CI
	$(eval _VAULT_LICENSE=$(shell printenv VAULT_LICENSE_CI))
else ifdef VAULT_LICENSE
	@echo Getting license from VAULT_LICENSE
	$(eval _VAULT_LICENSE=$(shell printenv VAULT_LICENSE))
else ifdef VAULT_LICENSE_PATH
	@echo Getting license from VAULT_LICENSE_PATH
	$(eval _VAULT_LICENSE=$(shell cat $(VAULT_LICENSE_PATH)))
	@test -n "$(_VAULT_LICENSE)" || ( echo vault license is empty; exit 1)
else
	$(error no valid vault license source provided, choices are VAULT_LICENSE_CI, VAULT_LICENSE, VAULT_LICENSE_PATH)
endif
endif

.PHONY: ci-deploy
ci-deploy: kustomize set-image ## Deploy controller to the K8s cluster (without generating assets)
	$(KUSTOMIZE) build $(KUSTOMIZE_BUILD_DIR) | kubectl apply -f -

.PHONY: ci-deploy-kind
ci-deploy-kind: load-docker-image ## Deploy controller to the K8s cluster (without generating assets)

.PHONY: load-docker-image
load-docker-image: kustomize ## Deploy controller to the K8s cluster (without generating assets)
	kind load docker-image --name $(KIND_CLUSTER_NAME) $(IMG)

.PHONY: teardown-integration-test
teardown-integration-test: ignore-not-found = true
teardown-integration-test: undeploy ## Teardown the integration test setup
	$(TERRAFORM) -chdir=$(TF_VAULT_STATE_DIR) destroy -auto-approve \
		-var k8s_config_context=$(KIND_CLUSTER_CONTEXT) \
		-var vault_enterprise=$(VAULT_ENTERPRISE) \
		-var vault_license=ignored && \
	rm -rf $(TF_VAULT_STATE_DIR)

##@ Generate Helm Chart
### Helmify regenerates the CRDs and copies them into the chart dir.
### NOTE: It will overwrite the existing templates dir so we have a TODO to figure out if there
### is a way to track diffs, or just do not commit the changes to the templates directory when
### regenerating the CRDs from the config directory.
.PHONY: helm-chart
helm-chart: manifests kustomize helmify
	$(KUSTOMIZE) build $(KUSTOMIZE_BUILD_DIR) | $(HELMIFY) -crd-dir

.PHONY: unit-test
unit-test: ## Run unit tests for the helm chart
	PATH="$(CURDIR)/scripts:$(PATH)" bats test/unit/

##@ EKS
.PHONY: create-eks
create-eks: ## Create a new EKS cluster
	$(TERRAFORM) -chdir=$(TF_EKS_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_EKS_DIR) apply -auto-approve
	$(AWS) eks --region $$($(TERRAFORM) -chdir=$(TF_EKS_DIR) output -raw region) update-kubeconfig \
    --name $$($(TERRAFORM) -chdir=$(TF_EKS_DIR) output -raw cluster_name)

.PHONY: port-forward
port-forward:
	@if lsof -Pi :38300 -sTCP:LISTEN -t >/dev/null ; then \
	    echo "Port 38300 is already in use, please free it up and try again."; \
	else \
	    echo "Starting port forwarding..."; \
	    bash -c 'trap exit SIGINT; while true; do kubectl port-forward -n $(K8S_VAULT_NAMESPACE) statefulset/vault 38300:8200; done'; \
	fi

# Currently only supports amd64
.PHONY: ci-ecr-build-push
ci-ecr-build-push: ## Build the operator image and push it to the ECR repository
	@$(eval IMG := $(shell $(TERRAFORM) -chdir=$(TF_EKS_DIR) output -raw ecr_url):$(VERSION))
	$(MAKE) ci-build ci-docker-build IMG=$(IMG)
	$(AWS) ecr get-login-password --region $$($(TERRAFORM) -chdir=$(TF_EKS_DIR) output -raw region) | docker login --username AWS --password-stdin $$($(TERRAFORM) -chdir=$(TF_EKS_DIR) output -raw ecr_url)
	docker push $(IMG)

.PHONY: integration-test-eks
integration-test-eks: ## Run integration tests in the EKS cluster
	@$(eval KIND_CLUSTER_CONTEXT := $(shell $(TERRAFORM) -chdir=$(TF_EKS_DIR) output -raw cluster_arn))
	@$(eval IMAGE_TAG_BASE := $(shell $(TERRAFORM) -chdir=$(TF_EKS_DIR) output -raw ecr_url))
	$(MAKE) port-forward &
	$(MAKE) integration-test KIND_CLUSTER_CONTEXT=$(KIND_CLUSTER_CONTEXT) IMAGE_TAG_BASE=$(IMAGE_TAG_BASE) IMG=$(IMAGE_TAG_BASE):$(VERSION)

.PHONY: ci-ecr-delete
ci-ecr-delete: ## Delete the ECR repository
	@$(eval AWS_REGION := $(shell $(TERRAFORM) -chdir=$(TF_EKS_DIR) output -raw region))
	@$(eval ECR_REPO_NAME := $(shell $(TERRAFORM) -chdir=$(TF_EKS_DIR) output -raw ecr_name))
	$(AWS) ecr batch-delete-image --region $(AWS_REGION) --repository-name $(ECR_REPO_NAME) --image-ids imageTag="$(VERSION)" || true;

.PHONY: destroy-eks
destroy-eks: ## Destroy the EKS cluster
	$(TERRAFORM) -chdir=$(TF_EKS_DIR) destroy -auto-approve

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize set-image ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build $(KUSTOMIZE_BUILD_DIR) | kubectl apply -f -

.PHONY: undeploy
undeploy: set-image ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build $(KUSTOMIZE_BUILD_DIR) | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy-kind
deploy-kind: manifests kustomize load-docker-image deploy ## Deploy controller to the K8s cluster specified in ~/.kube/config.

.PHONY: delete-operator-pod
delete-operator-pod:
	kubectl -n $(OPERATOR_NAMESPACE) delete pod  -l control-plane=controller-manager

.PHONY: rollout-restart-operator
rollout-restart-operator:
	kubectl -n $(OPERATOR_NAMESPACE) rollout restart deployment -l control-plane=controller-manager

.PHONY: build-deploy-kind
build-deploy-kind:
	$(MAKE) generate manifests docker-build deploy-kind delete-operator-pod

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest

## Tool Versions
KUSTOMIZE_VERSION ?= v4.5.7
CONTROLLER_TOOLS_VERSION ?= v0.11.1

KUSTOMIZE_INSTALL_SCRIPT ?= "./hack/install_kustomize.sh"
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	test -s $(LOCALBIN)/kustomize || $(KUSTOMIZE_INSTALL_SCRIPT) $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) go-version-check ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: bundle
bundle: manifests kustomize set-image ## Generate bundle manifests and metadata, then validate generated files.
	operator-sdk generate kustomize manifests -q
	$(KUSTOMIZE) build $(KUSTOMIZE_BUILD_DIR)/manifests | operator-sdk generate bundle $(BUNDLE_GEN_FLAGS)
	operator-sdk bundle validate ./bundle

.PHONY: bundle-build
bundle-build: ## Build the bundle image.
	docker build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) docker-push IMG=$(BUNDLE_IMG)

.PHONY: aws
AWS = ./bin/aws
aws: ## Download aws cli locally if necessary.
ifeq (,$(wildcard $(AWS)))
ifeq (,$(shell which $(notdir $(AWS)) 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(AWS)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sfSLo $(AWS).zip https://awscli.amazonaws.com/awscli-exe-$${OS}-$${ARCH}.zip -o "awscliv2.zip" ; \
	unzip awscliv2.zip -d $(dir $(AWS)) $(notdir $(AWS)) ;\
	rm -f awscliv2.zip ; \
	}
else
AWS = $(shell which aws)
endif
endif

.PHONY: opm
OPM = ./bin/opm
opm: ## Download opm locally if necessary.
ifeq (,$(wildcard $(OPM)))
ifeq (,$(shell which opm 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPM)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPM) https://github.com/operator-framework/operator-registry/releases/download/v1.23.0/$${OS}-$${ARCH}-opm ;\
	chmod +x $(OPM) ;\
	}
else
OPM = $(shell which opm)
endif
endif

.PHONY: terraform
TERRAFORM = ./bin/terraform
terraform: ## Download terraform locally if necessary.
ifeq (,$(wildcard $(TERRAFORM)))
ifeq (,$(shell which $(notdir $(TERRAFORM)) 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(TERRAFORM)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sfSLo $(TERRAFORM).zip https://releases.hashicorp.com/terraform/$(TERRAFORM_VERSION)/terraform_$(TERRAFORM_VERSION)_$${OS}_$${ARCH}.zip ; \
	unzip $(TERRAFORM).zip -d $(dir $(TERRAFORM)) $(notdir $(TERRAFORM)) ;\
	rm -f $(TERRAFORM).zip ; \
	}
else
TERRAFORM = $(shell which terraform)
endif
endif

.PHONY: gofumpt
GOFUMPT = ./bin/gofumpt
gofumpt: ## Download gofumpt locally if necessary.
ifeq (,$(wildcard $(GOFUMPT)))
ifeq (,$(shell which $(notdir $(GOFUMPT)) 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(GOFUMPT)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sfSLo $(GOFUMPT) https://github.com/mvdan/gofumpt/releases/download/$(GOFUMPT_VERSION)/gofumpt_$(GOFUMPT_VERSION)_$${OS}_$${ARCH} ; \
	chmod +x $(GOFUMPT) ; \
	}
else
GOFUMPT = $(shell which gofumpt)
endif
endif

HELMIFY = ./bin/helmify
helmify: ## Download helmify locally if necessary.
ifeq (,$(wildcard $(HELMIFY)))
ifeq (,$(shell which $(notdir $(HELMIFY)) 2>/dev/null))
	@{ \
	GOBIN=${LOCALBIN} go install github.com/arttor/helmify/cmd/helmify@${HELMIFY_VERSION} ;\
	}
else
HELMIFY = $(shell which helmify)
endif
endif

.PHONY: copywrite
copywrite: ## Download copywrite locally if necessary.
	@./hack/install_copywrite.sh
	$(eval COPYWRITE=./bin/copywrite)

# A comma-separated list of bundle images (e.g. make catalog-build BUNDLE_IMGS=example.com/operator-bundle:v0.1.0,example.com/operator-bundle:v0.2.0).
# These images MUST exist in a registry and be pull-able.
BUNDLE_IMGS ?= $(BUNDLE_IMG)

# The image tag given to the resulting catalog image (e.g. make catalog-build CATALOG_IMG=example.com/operator-catalog:v0.2.0).
CATALOG_IMG ?= $(IMAGE_TAG_BASE)-catalog:v$(VERSION)

# Set CATALOG_BASE_IMG to an existing catalog image tag to add $BUNDLE_IMGS to that image.
ifneq ($(origin CATALOG_BASE_IMG), undefined)
FROM_INDEX_OPT := --from-index $(CATALOG_BASE_IMG)
endif

# Build a catalog image by adding bundle images to an empty catalog using the operator package manager tool, 'opm'.
# This recipe invokes 'opm' in 'semver' bundle add mode. For more information on add modes, see:
# https://github.com/operator-framework/community-operators/blob/7f1438c/docs/packaging-operator.md#updating-your-existing-operator
.PHONY: catalog-build
catalog-build: opm ## Build a catalog image.
	$(OPM) index add --container-tool docker --mode semver --tag $(CATALOG_IMG) --bundles $(BUNDLE_IMGS) $(FROM_INDEX_OPT)

# Push the catalog image.
.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(MAKE) docker-push IMG=$(CATALOG_IMG)

.PHONY: build-diags
build-diags:
	./scripts/build-diags.sh

.PHONY: clean
clean:
	rm -rf build


# Generate Helm reference docs from values.yaml and update Vault website.
# Usage: make gen-helm-docs vault=<path-to-vault-repo>.
# If not options are given, the local copy of docs/helm.mdx will be updated, which can
# be used to submit a PR to vault docs.
# Adapted from https://github.com/hashicorp/consul-k8s/tree/main/hack/helm-reference-gen
gen-helm-docs:
	@cd hack/helm-reference-gen; go run ./... --vault=$(vault)
