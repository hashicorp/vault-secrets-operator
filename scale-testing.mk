# run the following from the project root:
# make -f scale-testing.mk <make rule>

# AWS variables for cloud hosted k8s testing
AWS_REGION ?= us-east-2
EKS_K8S_VERSION ?= 1.26

# directories for cloud hosted k8s infrastructure for running tests
# root directory for all integration tests
TF_EKS_SRC_DIR ?= $(INTEGRATION_TEST_ROOT)/infra/scale-testing
TF_EKS_STATE_DIR ?= $(TF_EKS_SRC_DIR)/state

include ./Makefile

##@ EKS

.PHONY: create-eks
create-eks: ## Create a new EKS cluster
	@mkdir -p $(TF_EKS_STATE_DIR)
	rm -f $(TF_EKS_STATE_DIR)/*.tf
	cp -v $(TF_EKS_SRC_DIR)/*.tf $(TF_EKS_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_EKS_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_EKS_STATE_DIR) apply -auto-approve \
		-var region=$(AWS_REGION) \
		-var kubernetes_version=$(EKS_K8S_VERSION) || exit 1
	rm -f $(TF_EKS_STATE_DIR)/*.tfvars

.PHONY: destroy-eks
destroy-eks: ## Destroy the EKS cluster
	$(TERRAFORM) -chdir=$(TF_EKS_STATE_DIR) destroy -auto-approve \
		-var region=$(AWS_REGION) \
		-var kubernetes_version=$(EKS_K8S_VERSION) || exit 1
