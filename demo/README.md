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
