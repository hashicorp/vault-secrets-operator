# VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the VERSION as arg of the bundle target (e.g make bundle VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export VERSION=0.0.2)
VERSION ?= 0.0.0-dev

VAULT_VERSION ?= latest
VAULT_IMAGE_REPO ?= hashicorp/vault
VAULT_ENT_IMAGE_REPO ?= hashicorp/vault-enterprise
K8S_VAULT_NAMESPACE ?= demo
KIND_K8S_VERSION ?= v1.25.3
LICENSE_TMP ?= $(TMPDIR)
VAULT_HELM_VERSION ?= 0.23.0
TESTARGS ?= '-test.v'

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
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.24.1

# Kind cluster name
KIND_CLUSTER_NAME ?= vault-secrets-operator

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
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	@sh -c "'$(CURDIR)/scripts/fix-copyright.sh'"

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run gofumpt against code.
	gofumpt -l -w .

.PHONY: fmtcheck
fmtcheck: ## Check formatting
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" go test ./... $(TESTARGS) -coverprofile cover.out

##@ Build

.PHONY: build
build: generate fmt vet ## Build manager binary.
	go build -o bin/vault-secrets-operator main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./main.go

.PHONY: docker-build
docker-build: test ## Build docker image with the manager.
	docker build -t $(IMG) . --target=dev --build-arg GO_VERSION=$(shell cat .go-version)

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push $(IMG)

##@ CI

.PHONY: ci-build
ci-build: ## Build operator binary (without generating assets).
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-a \
		-o $(BUILD_DIR)/$(BIN_NAME) \
		.

.PHONY: ci-docker-build
ci-docker-build: ## Build docker image with the operator (without generating assets)
	mkdir -p $(BUILD_DIR)/$(GOOS)/$(GOARCH)
	cp $(BUILD_DIR)/$(BIN_NAME) $(BUILD_DIR)/$(GOOS)/$(GOARCH)/$(BIN_NAME)
	docker build -t $(IMG) . --target release-default --build-arg GO_VERSION=$(shell cat .go-version)

.PHONY: ci-test
ci-test: vet envtest ## Run tests in CI (without generating assets)
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" go test ./... $(TESTARGS) -coverprofile cover.out

.PHONY: integration-test
integration-test: ## Run integration tests for Vault OSS
	INTEGRATION_TESTS=true KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) CGO_ENABLED=0 go test github.com/hashicorp/vault-secrets-operator/integrationtest/... $(TESTARGS) -count=1 -timeout=10m

.PHONY: integration-test-ent
integration-test-ent: ## Run integration tests for Vault ENT
	make integration-test ENT_TESTS=true

.PHONY: setup-kind
setup-kind: ## create a kind cluster for running the acceptance tests locally
	kind get clusters | grep --silent "^$(KIND_CLUSTER_NAME)$$" || \
	kind create cluster \
		--image kindest/node:$(KIND_K8S_VERSION) \
		--name $(KIND_CLUSTER_NAME)  \
		--config $(CURDIR)/integrationtest/kind/config.yaml
	kubectl config use-context kind-$(KIND_CLUSTER_NAME)

.PHONY: delete-kind
delete-kind: ## delete the kind cluster
	kind delete cluster --name $(KIND_CLUSTER_NAME) || true

.PHONY: setup-integration-test-common
## Create Vault inside the cluster
setup-integration-test-common: SET_LICENSE=$(if $(VAULT_LICENSE_CI),--set server.enterpriseLicense.secretName=vault-license)
setup-integration-test-common: teardown-integration-test
	kubectl create namespace $(K8S_VAULT_NAMESPACE)

	# don't log the license
	printenv VAULT_LICENSE_CI > $(LICENSE_TMP)/vault-license.txt || true
	if [ -s $(LICENSE_TMP)/vault-license.txt ]; then \
		kubectl -n $(K8S_VAULT_NAMESPACE) create secret generic vault-license --from-file license=$(LICENSE_TMP)/vault-license.txt; \
		rm -rf $(LICENSE_TMP)/vault-license.txt; \
	fi

	helm install vault vault --repo https://helm.releases.hashicorp.com --version=$(VAULT_HELM_VERSION) \
		--wait --timeout=5m \
		--namespace=$(K8S_VAULT_NAMESPACE) \
		--create-namespace \
		--set server.logLevel=debug \
		--set server.dev.enabled=true \
		--set server.image.tag=$(VAULT_VERSION) \
		--set server.image.repository=$(VAULT_IMAGE_REPO) \
		$(SET_LICENSE) \
		--set injector.enabled=false
	kubectl patch --namespace=$(K8S_VAULT_NAMESPACE) statefulset vault --patch-file integrationtest/vault/hostPortPatch.yaml

	kubectl delete --namespace=$(K8S_VAULT_NAMESPACE) pod vault-0
	kubectl wait --namespace=$(K8S_VAULT_NAMESPACE) --for=condition=Ready --timeout=5m pod -l app.kubernetes.io/name=vault


.PHONY: setup-integration-test
setup-integration-test: setup-integration-test-common ci-docker-build ci-deploy-kind ## Setup the integration test (Vault OSS, build and deploy operator)

.PHONY: setup-integration-test-ent
setup-integration-test-ent: VAULT_IMAGE_REPO=$(VAULT_ENT_IMAGE_REPO)
setup-integration-test-ent: check-license setup-integration-test-common ci-docker-build ci-deploy-kind ## Setup the integration test (Vault ENT, build and deploy operator)

.PHONY: ci-deploy
ci-deploy: kustomize ## Deploy controller to the K8s cluster (without generating assets)
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: ci-deploy-kind
ci-deploy-kind: kustomize ## Deploy controller to the K8s cluster (without generating assets)
	kind load docker-image --name $(KIND_CLUSTER_NAME) $(IMG)
	make ci-deploy

.PHONY: check-license
## check that VAULT_LICENSE_CI is set
check-license:
	(printenv VAULT_LICENSE_CI > /dev/null) || (echo "VAULT_LICENSE_CI must be set"; exit 1)

.PHONY: teardown-integration-test
teardown-integration-test: ignore-not-found = true
teardown-integration-test: undeploy ## Teardown the integration test setup
	helm uninstall vault --namespace=$(K8S_VAULT_NAMESPACE) || true
	kubectl delete --ignore-not-found namespace $(K8S_VAULT_NAMESPACE)

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
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy-kind
deploy-kind: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	kind load docker-image --name $(KIND_CLUSTER_NAME) $(IMG)
	make deploy

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
KUSTOMIZE_VERSION ?= v4.5.6
CONTROLLER_TOOLS_VERSION ?= v0.11.1

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	curl -s $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: bundle
bundle: manifests kustomize ## Generate bundle manifests and metadata, then validate generated files.
	operator-sdk generate kustomize manifests -q
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/manifests | operator-sdk generate bundle $(BUNDLE_GEN_FLAGS)
	operator-sdk bundle validate ./bundle

.PHONY: bundle-build
bundle-build: ## Build the bundle image.
	docker build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) docker-push IMG=$(BUNDLE_IMG)

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
