# run the following from the project root:
# make -f gcp.mk <make rule>

# Google Cloud variables for cloud hosted k8s testing
GCP_REGION ?= us-west1
GCP_PROJECT ?=

# directories for cloud hosted k8s infrastructure for running tests
TF_GKE_SRC_DIR ?= $(INTEGRATION_TEST_ROOT)/infra/gke
TF_GKE_STATE_DIR ?= $(TF_GKE_SRC_DIR)/state

include ./Makefile

##@ GKE

.PHONY: create-gke
create-gke: ## Create a new GKE cluster
	@mkdir -p $(TF_GKE_STATE_DIR)
	cp -v $(TF_GKE_SRC_DIR)/*.tf $(TF_GKE_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_GKE_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_GKE_STATE_DIR) apply -auto-approve \
		-var region=$(GCP_REGION) \
		-var project_id=$(GCP_PROJECT) || exit 1 \
	rm -f $(TF_GKE_STATE_DIR)/*.tfvars
	gcloud container clusters get-credentials \
	$$($(TERRAFORM) -chdir=$(TF_GKE_STATE_DIR) output -raw kubernetes_cluster_name) --region $(GCP_REGION)

.PHONY: import-gcp-vars
import-gcp-vars:
-include $(TF_GKE_STATE_DIR)/outputs.env

.PHONY: build-push
build-push: import-gcp-vars ci-build ci-docker-build ## Build the operator image and push it to the GAR repository
	gcloud auth configure-docker $(GCP_REGION)-docker.pkg.dev
	docker push $(IMG)

.PHONY: integration-test-gke
integration-test-gke: export SKIP_GCP_TESTS=false
integration-test-gke: ## Run integration tests in the GKE cluster
	$(MAKE) port-forward &
	$(MAKE) integration-test K8S_CLUSTER_CONTEXT=$(K8S_CLUSTER_CONTEXT) IMAGE_TAG_BASE=$(IMAGE_TAG_BASE) \
	IMG=$(IMG) VAULT_OIDC_DISC_URL=$(GKE_OIDC_URL) VAULT_OIDC_CA=false \
	GCP_REGION=$(GCP_REGION) GCP_PROJECT=$(GCP_PROJECT) GKE_CLUSTER_NAME=$(GKE_CLUSTER_NAME) \
	SKIP_HCPVSAPPS_TESTS=true

.PHONY: destroy-gke
destroy-gke: ## Destroy the GKE cluster
	$(TERRAFORM) -chdir=$(TF_GKE_STATE_DIR) destroy -auto-approve \
		-var region=$(GCP_REGION) \
		-var project_id=$(GCP_PROJECT) || exit 1
