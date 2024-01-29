## Vault Secrets Operator Demo (Dynamic Secrets)

Brings up a kind cluster running Vault, the Vault Secrets Operator, Postgres, and a simple Deployment application.

To run the demo, perform the following from the project root

If you haven't already built the vault-secrets-operator Docker image run:
```shell
make docker-build
```

Deploy the demo app:
```shell
make -f demo.mk demo
```

You can poke around on the demo cluster using one of your favorite tools.

Run the following to tear down the demo cluster:
```shell
make -f demo.mk demo-destroy
```

### Vault Enterprise
If you want to demo VSO's support for Vault Enterprise features like cross namespace authentication
for multi-tenancy, you can extend the commands above by adding `VAULT_ENTERPRISE=true` to each.
A valid Vault Enterprise license is required. You can set the license from any of the following
environment variables:
- VAULT_LICENSE
- VAULT_LICENSE_PATH

Deploy the demo app:
```shell
make -f demo.mk VAULT_ENTERPRISE=true demo
```
