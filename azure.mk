# run the following from the project root:
# make -f azure.mk <make rule>

# Azure variables cloud hosted k8s testing
AZURE_REGION ?= West US 2
AKS_K8S_VERSION ?= 1.25.6
ACR_REPO_NAME ?= vso

# directories for cloud hosted k8s infrastructure for running tests
TF_AKS_SRC_DIR ?= $(INTEGRATION_TEST_ROOT)/infra/aks
TF_AKS_STATE_DIR ?= $(TF_AKS_SRC_DIR)/state

include ./Makefile

##@ AKS

.PHONY: create-aks
create-aks: ## Create a new AKS cluster
	@mkdir -p $(TF_AKS_STATE_DIR)
	cp -v $(TF_AKS_SRC_DIR)/*.tf $(TF_AKS_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_AKS_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_AKS_STATE_DIR) apply -auto-approve \
		-var region="$(AZURE_REGION)" \
		-var kubernetes_version=$(AKS_K8S_VERSION) \
		-var container_repository_name=$(ACR_REPO_NAME) || exit 1 \
	rm -f $(TF_AKS_STATE_DIR)/*.tfvars

.PHONY: import-azure-vars
import-azure-vars:
-include $(TF_AKS_STATE_DIR)/outputs.env

# Currently only supports amd64
.PHONY: build-push
build-push: import-azure-vars ci-build ci-docker-build ## Build the operator image and push it to the ACR repository
	az acr login --name $(ACR_NAME)
	docker push $(IMG)

.PHONY: integration-test-aks
integration-test-aks: build-push ## Run integration tests in the AKS cluster
	az aks get-credentials --resource-group $(AZURE_RSG_NAME) update-kubeconfig --name $(AKS_CLUSTER_NAME)
	$(MAKE) port-forward &
	$(MAKE) integration-test K8S_CLUSTER_CONTEXT=$(K8S_CLUSTER_CONTEXT) IMAGE_TAG_BASE=$(IMAGE_TAG_BASE) \
	IMG=$(IMG) VAULT_OIDC_DISC_URL=$(AZ_OIDC_URL) VAULT_OIDC_CA=false

.PHONY: destroy-aks
destroy-aks: ## Destroy the AKS cluster
	$(TERRAFORM) -chdir=$(TF_AKS_STATE_DIR) destroy -auto-approve \
		-var region="$(AZURE_REGION)" \
		-var kubernetes_version=$(AKS_K8S_VERSION) \
		-var container_repository_name=$(ACR_REPO_NAME) || exit 1
