# run the following from the project root:
# make -f aws.mk <make rule>

# AWS variables for cloud hosted k8s testing
AWS_REGION ?= us-east-2
EKS_K8S_VERSION ?= 1.26

# directories for cloud hosted k8s infrastructure for running tests
TF_EKS_SRC_DIR ?= $(INTEGRATION_TEST_ROOT)/infra/eks
TF_EKS_STATE_DIR ?= $(TF_EKS_SRC_DIR)/state

include ./Makefile

##@ EKS

.PHONY: create-eks
create-eks: ## Create a new EKS cluster
	@mkdir -p $(TF_EKS_STATE_DIR)
	cp -v $(TF_EKS_SRC_DIR)/*.tf $(TF_EKS_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_EKS_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_EKS_STATE_DIR) apply -auto-approve \
		-var region=$(AWS_REGION) \
		-var kubernetes_version=$(EKS_K8S_VERSION) || exit 1 \
	rm -f $(TF_EKS_STATE_DIR)/*.tfvars

.PHONY: import-aws-vars
import-aws-vars:
-include $(TF_EKS_STATE_DIR)/outputs.env

.PHONY: build-push
build-push: import-aws-vars ci-build ci-docker-build ## Build the operator image and push it to the GAR repository
	aws ecr get-login-password --region $(AWS_REGION) | docker login --username AWS --password-stdin $(ECR_URL)
	docker push $(IMG)

.PHONY: integration-test-eks
integration-test-eks: build-push ## Run integration tests in the EKS cluster
	aws eks --region $(AWS_REGION) update-kubeconfig --name $(EKS_CLUSTER_NAME)
	$(MAKE) port-forward &
	$(MAKE) integration-test K8S_CLUSTER_CONTEXT=$(K8S_CLUSTER_CONTEXT) IMAGE_TAG_BASE=$(IMAGE_TAG_BASE) \
	IMG=$(IMG) VAULT_OIDC_DISC_URL=$(EKS_OIDC_URL) VAULT_OIDC_CA=false \
	AWS_REGION=$(AWS_REGION) AWS_IRSA_ROLE=$(IRSA_ROLE) AWS_ACCOUNT_ID=$(ACCOUNT_ID) \
	SKIP_AWS_TESTS=false SKIP_AWS_STATIC_CREDS_TEST=true

.PHONY: destroy-ecr
destroy-ecr: ## Destroy the ECR repository
	aws ecr batch-delete-image --region $(AWS_REGION) --repository-name $(ECR_REPO_NAME) --image-ids imageTag="$(VERSION)" || true;

.PHONY: destroy-eks
destroy-eks: destroy-ecr ## Destroy the EKS cluster
	$(TERRAFORM) -chdir=$(TF_EKS_STATE_DIR) destroy -auto-approve \
		-var region=$(AWS_REGION) \
		-var kubernetes_version=$(EKS_K8S_VERSION) || exit 1
