# run the following from the project root:
# make -f demo.mk demo
# that will bring up a kind cluster running the Operator along with a simple app
# that demonstrates dynamic Vault secrets.

DEMO_ROOT = ./demo
# Kind cluster name (demo)
KIND_CLUSTER_NAME ?= vso-demo
# Kind config file
KIND_CONFIG_FILE ?= $(DEMO_ROOT)/kind/config.yaml
# Kubernetes cluster context (demo), defaults to the Kind cluster
K8S_CLUSTER_CONTEXT ?= kind-$(KIND_CLUSTER_NAME)

TF_INFRA_DEMO_ROOT ?= $(DEMO_ROOT)/infra
TF_INFRA_DEMO_DIR_VAULT ?= $(DEMO_ROOT)/infra/vault
TF_VAULT_STATE_DIR ?= $(TF_INFRA_DEMO_DIR_VAULT)/state
TF_APP_STATE_DIR ?= $(TF_INFRA_DEMO_ROOT)/app/state

# install VSO using Helm, otherwise use Kustomize.
WITH_HELM ?= true

include ./Makefile

.PHONY: demo-setup-kind
demo-setup-kind: ## create a kind cluster for running the acceptance tests locally
	$(MAKE) setup-kind load-docker-image \
		KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) \
		KIND_CONFIG_FILE=$(KIND_CONFIG_FILE) \
		K8S_CLUSTER_CONTEXT=$(K8S_CLUSTER_CONTEXT)

.PHONY: demo-delete-kind
demo-delete-kind: ## delete the kind cluster
	@kind delete cluster --name $(KIND_CLUSTER_NAME) || true
	@find $(DEMO_ROOT) -type f -name '*tfstate*' | xargs rm &> /dev/null || true

.PHONY: demo-destroy
demo-destroy: demo-delete-kind ## delete the kind cluster

.PHONY: demo-infra-vault
demo-infra-vault: ## Deploy Vault for the demo
	$(MAKE) setup-vault \
		VAULT_ENTERPRISE=$(VAULT_ENTERPRISE) \
		TF_VAULT_STATE_DIR=$(TF_VAULT_STATE_DIR) \
		TF_INFRA_STATE_DIR=$(TF_VAULT_STATE_DIR) \
		K8S_CLUSTER_CONTEXT=$(K8S_CLUSTER_CONTEXT) \
		VAULT_PATCH_ROOT=$(DEMO_ROOT)/infra/vault

.PHONY: demo-infra-app
demo-infra-app: demo-setup-kind maybe-apply-crds ## Deploy Postgres for the demo
	@mkdir -p $(TF_APP_STATE_DIR)
	rm -f $(TF_APP_STATE_DIR)/*.tf
	rm -f $(TF_APP_STATE_DIR)/modules
	cp $(DEMO_ROOT)/infra/app/*.tf $(TF_APP_STATE_DIR)/.
	ln -s ../modules $(TF_APP_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_APP_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_APP_STATE_DIR) apply -auto-approve \
		-var vault_enterprise=$(VAULT_ENTERPRISE) \
		-var vault_address=http://127.0.0.1:38302 \
		-var vault_token=root \
		-var k8s_config_context=$(K8S_CLUSTER_CONTEXT) \
		-var deploy_operator_via_helm=$(WITH_HELM) \
		$(EXTRA_VARS) || exit 1 \

.PHONY: maybe-apply-crds
maybe-apply-crds:
ifneq ($(strip $(WITH_HELM)),)
	kubectl apply --recursive --filename $(CHART_CRDS_DIR) > /dev/null
endif

.PHONY: demo-infra-app-plan
demo-infra-app-plan: demo-setup-kind maybe-apply-crds ## Deploy Postgres for the demo
	@mkdir -p $(TF_APP_STATE_DIR)
	rm -f $(TF_APP_STATE_DIR)/*.tf
	cp $(DEMO_ROOT)/infra/app/*.tf $(TF_APP_STATE_DIR)/.
	rm -f $(TF_APP_STATE_DIR)/modules
	ln -s ../modules $(TF_APP_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_APP_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_APP_STATE_DIR) plan \
		-var vault_enterprise=$(VAULT_ENTERPRISE) \
		-var vault_address=http://127.0.0.1:38302 \
		-var vault_token=root \
		-var k8s_config_context=$(K8S_CLUSTER_CONTEXT) \
		-var deploy_operator_via_helm=$(WITH_HELM) \
		$(EXTRA_VARS) || exit 1 \

.PHONY: demo-infra-app-destroy
demo-infra-app-destroy: demo-setup-kind ## Destroy the application portion of the demo
	@mkdir -p $(TF_APP_STATE_DIR)
	rm -f $(TF_APP_STATE_DIR)/*.tf
	rm -f $(TF_APP_STATE_DIR)/modules
	cp $(DEMO_ROOT)/infra/app/*.tf $(TF_APP_STATE_DIR)/.
	ln -s ../modules $(TF_APP_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_APP_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_APP_STATE_DIR) apply -destroy -auto-approve \
		-var vault_enterprise=$(VAULT_ENTERPRISE) \
		-var vault_address=http://127.0.0.1:38302 \
		-var vault_token=root \
		-var k8s_config_context=$(K8S_CLUSTER_CONTEXT) \
		-var deploy_operator_via_helm=$(WITH_HELM) \
		$(EXTRA_VARS) || exit 1 \

.PHONY: demo-deploy
demo-deploy: demo-setup-kind ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	$(MAKE) deploy-kind \
		KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) \
		KUSTOMIZATION=persistence-encrypted-test

.PHONY: demo
#demo: demo-deploy demo-infra-vault demo-infra-app ## Deploy the demo
demo: demo-setup-kind demo-infra-vault demo-infra-app ## Deploy the demo
