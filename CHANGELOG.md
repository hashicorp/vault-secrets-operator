## Unreleased

Bugs:
* Helm Chart: fix deployment templating so setting `controller.kubernetesClusterDomain` works as defined in values.yaml. [GH-183](https://github.com/hashicorp/vault-secrets-operator/pull/183)

Features:
* VaultDynamicSecrets (VDS): CRD is extended with `Revoke` field which will result in the dynamic secret lease being revoked on rotation and CR deletion. Note: The VaultAuthMethod referenced by the VDS Secret must have a policy which provides `["update"]` on `sys/leases/revoke`. [GH-143](https://github.com/hashicorp/vault-secrets-operator/pull/143)
* VaultAuth: Adds support for the JWT authentication method which either uses the JWT token from the provided secret reference, or a service account JWT token that VSO will generate using the provided service account. [GH-131](https://github.com/hashicorp/vault-secrets-operator/pull/131)
* VaultDynamicSecrets (VDS): New `RenewalPercent` field to control when a lease is renewed [GH-170](https://github.com/hashicorp/vault-secrets-operator/pull/170)

Improvements:
* VaultDynamicSecrets (VDS): Generate new credentials if lease renewal TTL is truncated [GH-170](https://github.com/hashicorp/vault-secrets-operator/pull/170)
* VaultDynamicSecrets (VDS): Replace `Spec.Role` with `Spec.Path` (**breaking change**) [GH-172](https://github.com/hashicorp/vault-secrets-operator/pull/172)

## 0.1.0-beta (March 29th, 2023)

* Initial Beta Release
