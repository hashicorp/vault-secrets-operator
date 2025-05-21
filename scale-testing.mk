# run the following from the project root:
# make -f scale-testing.mk <make rule>

# AWS variables for cloud hosted k8s testing
AWS_REGION ?= us-east-2
EKS_K8S_VERSION ?= 1.30

#OPERATOR_NAMESPACE ?= vault-secrets-operator-system
#IMAGE_TAG_BASE ?= hashicorp/vault-secrets-operator
#K8S_VAULT_NAMESPACE ?= vault
VERSION ?= 0.8.1
INTEGRATION_TESTS_PARALLEL ?= true
SKIP_HCPVSAPPS_TESTS ?= true

# directories for cloud hosted k8s infrastructure for running tests
# root directory for all integration tests
TF_EKS_SRC_DIR ?= $(INTEGRATION_TEST_ROOT)/infra/scale-testing/eks-cluster
TF_EKS_STATE_DIR ?= $(TF_EKS_SRC_DIR)/state
TF_EKS_PROMETHEUS_SRC_DIR ?= $(INTEGRATION_TEST_ROOT)/infra/scale-testing/eks-prometheus
TF_EKS_PROMETHEUS_STATE_DIR ?= $(TF_EKS_PROMETHEUS_SRC_DIR)/state
TF_DEPLOY_SRC_DIR ?= $(INTEGRATION_TEST_ROOT)/infra/scale-testing/deployments
TF_DEPLOY_STATE_DIR ?= $(TF_DEPLOY_SRC_DIR)/state
SCALE_TESTS=1

include ./Makefile

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

.PHONY: create-eks-prometheus
create-eks-prometheus: ##
	@mkdir -p $(TF_EKS_PROMETHEUS_STATE_DIR)
	rm -f $(TF_EKS_PROMETHEUS_STATE_DIR)/*.tf
	cp -v $(TF_EKS_PROMETHEUS_SRC_DIR)/*.tf $(TF_EKS_PROMETHEUS_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_EKS_PROMETHEUS_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_EKS_PROMETHEUS_STATE_DIR) apply -auto-approve \
		-var region=$(AWS_REGION) \
		-var prometheus_k8s_namespace=$(PROMETHEUS_K8S_NAMESPACE) \
		-var amsp_ingest_sa=$(AMSP_INGEST_SA) \
		-var iam_proxy_prometheus_role_arn=$(IAM_PROXY_PROMETHEUS_ROLE_ARN) || exit 1
	rm -f $(TF_EKS_STATE_DIR)/*.tfvars

.PHONY: destroy-eks-prometheus
destroy-eks-prometheus: ## Destroy the EKS cluster
	$(TERRAFORM) -chdir=$(TF_EKS_PROMETHEUS_STATE_DIR) destroy -auto-approve \
		-var region=$(AWS_REGION) \
		-var prometheus_k8s_namespace=$(PROMETHEUS_K8S_NAMESPACE) \
		-var amsp_ingest_sa=$(AMSP_INGEST_SA) \
		-var iam_proxy_prometheus_role_arn=$(IAM_PROXY_PROMETHEUS_ROLE_ARN) || exit 1

.PHONY: deploy-workload
deploy-workload: set-vault-license ## Deploy the workload to the EKS cluster
	@mkdir -p $(TF_DEPLOY_STATE_DIR)
ifeq ($(VAULT_ENTERPRISE), true)
    ## ensure that the license is *not* emitted to the console
	@echo "vault_license = \"$(_VAULT_LICENSE)\"" > $(TF_DEPLOY_STATE_DIR)/license.auto.tfvars
endif
	rm -f $(TF_DEPLOY_STATE_DIR)/*.tf
	cp -v $(TF_DEPLOY_SRC_DIR)/*.tf $(TF_DEPLOY_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_DEPLOY_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_DEPLOY_STATE_DIR) apply -auto-approve || exit 1
	rm -f $(TF_DEPLOY_STATE_DIR)/*.tfvars

.PHONY: import-aws-vars
import-aws-vars:
-include $(TF_EKS_STATE_DIR)/outputs.env

.PHONY: connect-cluster
connect-cluster: import-aws-vars ## Connect to the EKS cluster
	aws eks --region $(AWS_REGION) update-kubeconfig --name $(EKS_CLUSTER_NAME)

.PHONY: cleanup-port-forward
cleanup-port-forward: ## Kill orphan port-forward processes
	@echo "Cleaning up orphan port-forward processes..."
	@pgrep -f 'kubectl port-forward -n $(K8S_VAULT_NAMESPACE) statefulset/vault' | xargs -r kill -9 && \
		echo "Port-forward processes terminated successfully." || \
		echo "No port-forward processes found or an error occurred."

.PHONY: set image scale-tests
scale-tests: cleanup-port-forward set-image connect-cluster import-aws-vars
	$(MAKE) port-forward &
	SCALE_TESTS=true VAULT_ENTERPRISE=true ENT_TESTS=$(VAULT_ENTERPRISE) \
	SUPPRESS_TF_OUTPUT=$(SUPPRESS_TF_OUTPUT) SKIP_CLEANUP=$(SKIP_CLEANUP) \
	OPERATOR_IMAGE_REPO=$(IMAGE_TAG_BASE) OPERATOR_IMAGE_TAG=$(VERSION) \
	OPERATOR_NAMESPACE=$(OPERATOR_NAMESPACE) \
	VAULT_OIDC_DISC_URL=$(EKS_OIDC_URL) VAULT_OIDC_CA=false \
	INTEGRATION_TESTS=true EKS_CLUSTER_NAME=$(EKS_CLUSTER_NAME) K8S_CLUSTER_CONTEXT=$(K8S_CLUSTER_CONTEXT) CGO_ENABLED=0 \
	K8S_VAULT_NAMESPACE=$(K8S_VAULT_NAMESPACE) \
	SKIP_AWS_TESTS=$(SKIP_AWS_TESTS) SKIP_AWS_STATIC_CREDS_TEST=$(SKIP_AWS_STATIC_CREDS_TEST) \
	SKIP_GCP_TESTS=$(SKIP_GCP_TESTS) SKIP_HCPVSAPPS_TESTS=$(SKIP_HCPVSAPPS_TESTS) \
	PARALLEL_INT_TESTS=$(INTEGRATION_TESTS_PARALLEL) \
	go test github.com/hashicorp/vault-secrets-operator/test/integration/... $(TESTARGS) -timeout=30m

.PHONY: destroy-eks
destroy-eks: ## Destroy the EKS cluster
	$(TERRAFORM) -chdir=$(TF_EKS_STATE_DIR) destroy -auto-approve \
		-var region=$(AWS_REGION) \
		-var kubernetes_version=$(EKS_K8S_VERSION) || exit 1
