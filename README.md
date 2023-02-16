# vault-secrets-operator

Kubernetes operator for Vault secrets synchronization

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
make build deploy-kind

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
