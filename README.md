# Vault Secrets Operator

The Vault Secrets Operator (VSO) allows Pods to consume Vault secrets natively from Kubernetes Secrets.

## Overview

The Vault Secrets Operator operates by watching for changes to its supported set of Custom Resource Definitions (CRD).
Each CRD provides the specification required to allow the *Operator* to synchronize a Vault Secrets to a Kubernetes Secret.
The *Operator* writes the *source* Vault secret data directly to the *destination* Kubernetes Secret, ensuring that any
changes made to the *source* are replicated to the *destination* over its lifetime. In this way, an application only needs
to have access to the *destination* secret in order to make use of the secret data contained within.

See the developer docs for more info [here](https://developer.hashicorp.com/vault/docs/platform/k8s/vso)

### Features

The following features are supported by the Vault Secrets Operator:

- All Vault secret engines supported.
- TLS/mTLS communications with Vault.
- Authentication using the requesting `Pod`'s `ServiceAccount` via the [Kubernetes Auth Method](https://developer.hashicorp.com/vault/docs/auth/kubernetes)
- Syncing Vault Secrets to Kubernetes Secrets.
- Secret rotation for `Deployment`, `ReplicaSet`, `StatefulSet` Kubernetes resource types.
- Prometheus' instrumentation for monitoring the *Operator*
- Supported installation methods: `Helm`, `Kustomize`

## Samples

Setup kubernetes and deploy the samples:

```shell
# Start a KinD cluster
make setup-kind

# Deploy Vault
make setup-integration-test

# Configure Vault
./config/samples/setup.sh

# Build and deploy the operator
make build docker-build deploy-kind

# Deploy the sample K8s resources
kubectl apply -k config/samples
```

Inspect the resulting secrets:

```shell
kubectl get secrets -n tenant-1 secret1 -o yaml

kubectl get secrets -n tenant-1 pki1 -o yaml

kubectl get secrets -n tenant-2 secret1 -o yaml
```

Delete the samples:

```shell
kubectl delete -k config/samples
```

### Ingress TLS with VaultPKISecret

The file `config/samples/secrets_v1beta1_vaultpkisecret_tls.yaml` contains an
example of using VaultPKISecret to populate a TLS secret for use with an
Ingress. This sample takes a little more setup to test it out (derived from the
[kind docs](https://kind.sigs.k8s.io/docs/user/ingress/)).

The TLS example is part of the samples, so setup kind, configure Vault, and
deploy the operator as described above.

Then deploy the nginx ingress controller:

```shell
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=90s
```

Check the deployed app with something like curl, it should return the `tls-app`
hostname, and the certificate should have a ~1.5m TTL:

```shell
$ curl -k https://localhost:38443/tls-app/hostname
tls-app

$ curl -kvI https://localhost:38443/tls-app/hostname
...
* Server certificate:
*  subject: CN=localhost
*  start date: Mar 17 05:53:28 2023 GMT
*  expire date: Mar 17 05:54:58 2023 GMT
*  issuer: CN=example.com
...
```

Watch the nginx controller logs to see the TLS secret being rotated:

```shell
kubectl logs -f -n ingress-nginx -l app.kubernetes.io/instance=ingress-nginx
```

## Tests

### Unit Tests

```shell
make test
```

### Integration Tests

```shell
# Start a KinD cluster
make setup-kind

# Build the operator binary, image, and deploy to the KinD cluster
make ci-build ci-docker-build ci-deploy-kind ci-deploy

# Run the integration tests (includes Vault deployment)
make integration-test
```

### Integration Tests in EKS

```shell
# Create an EKS cluster and a ECR repository
make -f aws.mk create-eks

# Build the operator image and run the integration tests (includes Vault Community deployment)
make -f aws.mk build-push integration-test-eks

# Run the integration tests (includes Vault ent deployment, have the Vault license as environment variable)
make -f aws.mk build-push integration-test-eks VAULT_ENTERPRISE=true ENT_TESTS=true
```

#### AWS auth test with static credentials

```shell
# Set SKIP_AWS_STATIC_CREDS_TEST=false and set the credentials for the static creds user via the environment variables TEST_AWS_ACCESS_KEY_ID,
# TEST_AWS_SECRET_ACCESS_KEY, TEST_AWS_STATIC_CREDS_ROLE (and TEST_AWS_SESSION_TOKEN if applicable) for a user in AWS.
# Note: these credentials will be set in a Kubernetes secret.
export TEST_AWS_ACCESS_KEY_ID="..."
export TEST_AWS_SECRET_ACCESS_KEY="..."
export TEST_AWS_SESSION_TOKEN="..."
export AWS_STATIC_CREDS_ROLE="arn:aws:iam::..."
make -f aws.mk integration-test-eks TESTARGS="-run TestVaultAuth" SKIP_AWS_STATIC_CREDS_TEST=false
```

### Integration Tests in GKE

```shell
# Export the Google Cloud project id
export GCP_PROJECT="<project_id>"

# Create an GKE cluster and a GAR repository
make -f gcp.mk create-gke

# Build & operator image & run the integration tests (includes Vault Community deployment)
make -f gcp.mk build-push integration-test-gke

# Run the integration tests (includes Vault ent deployment, have the Vault license as environment variable)
make -f gcp.mk build-push integration-test-gke VAULT_ENTERPRISE=true ENT_TESTS=true
```

### Integration Tests in AKS

```shell
# Export the Azure credentials
az config set core.allow_broker=true && az account clear && az login
az account set --subscription "<subscription_id>"
az ad sp create-for-rbac --name "vault-secrets-operator" --role "Owner" --scopes /subscriptions/<subscription_id> --output json
export AZURE_APPID="<app_id>"
export AZURE_PASSWORD="<password>"
export AZURE_TENANT="<tenant_id>"

# Create an AKS cluster and a ACR repository
make -f azure.mk create-aks

# Build  the operator image and run the integration tests (includes Vault Community deployment)
make -f azure.mk build-push integration-test-aks

# Run the integration tests (includes Vault ent deployment, have the Vault license as environment variable)
make -f azure.mk build-push integration-test-aks VAULT_ENTERPRISE=true ENT_TESTS=true
```
