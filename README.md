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

The file `config/samples/secrets_v1alpha1_vaultpkisecret_tls.yaml` contains an
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
