## Vault Secrets Operator Demo (pre-beta)

### The vault-secrets-operator is a Kubernetes Operator that knows how to sync a Vault Secret to a Kubernetes secret.

### It allows the practioner/developer to easily integrate their apps/workflows to consume Vault secrets from Kubernetes. *blissfully unaware of Vault.*

## Supported Secret Types

### - Static: kv-v1, kv-v2
### - PKI: TLS certificates
### - Dynamic: database, cloud, etc.

## Demo Agenda

### - Provide an overview of the operator, CRDs, auth mechanism
### - Deploy a demo app that will consume a k8s secret that was provisioned 
###   by the Operator from a Postgres secrets engine.
### - Demonstrate the way that the Operator handles dynamic secret revocation.

## Next steps

### - Wrap everything up for the public beta (last week of March)

## References

- RFC: VLT-227

## Thanks!
