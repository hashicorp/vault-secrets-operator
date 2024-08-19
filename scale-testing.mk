# run the following from the project root:
# make -f scale-testing.mk <make rule>

# AWS variables for cloud hosted k8s testing
AWS_REGION ?= us-east-2
EKS_K8S_VERSION ?= 1.30

# directories for cloud hosted k8s infrastructure for running tests
# root directory for all integration tests
TF_EKS_SRC_DIR ?= $(INTEGRATION_TEST_ROOT)/infra/scale-testing
TF_EKS_STATE_DIR ?= $(TF_EKS_SRC_DIR)/state

include ./Makefile

##@ EKS

.PHONY: create-eks
create-eks: set-vault-license ## Create a new EKS cluster
	@mkdir -p $(TF_EKS_STATE_DIR)
ifeq ($(VAULT_ENTERPRISE), true)
    ## ensure that the license is *not* emitted to the console
	@echo "vault_license = \"$(_VAULT_LICENSE)\"" > $(TF_EKS_STATE_DIR)/license.auto.tfvars
endif
	rm -f $(TF_EKS_STATE_DIR)/*.tf
	cp -v $(TF_EKS_SRC_DIR)/*.tf $(TF_EKS_STATE_DIR)/.
	$(TERRAFORM) -chdir=$(TF_EKS_STATE_DIR) init -upgrade
	$(TERRAFORM) -chdir=$(TF_EKS_STATE_DIR) apply -auto-approve \
		-var region=$(AWS_REGION) \
		-var kubernetes_version=$(EKS_K8S_VERSION) || exit 1
	rm -f $(TF_EKS_STATE_DIR)/*.tfvars

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

.PHONY: destroy-eks
destroy-eks: ## Destroy the EKS cluster
	$(TERRAFORM) -chdir=$(TF_EKS_STATE_DIR) destroy -auto-approve \
		-var region=$(AWS_REGION) \
		-var kubernetes_version=$(EKS_K8S_VERSION) || exit 1
