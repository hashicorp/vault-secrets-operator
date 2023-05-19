## Unreleased

Bugs:
* Helm Chart: fix deployment templating so setting `controller.kubernetesClusterDomain` works as defined in values.yaml. [GH-183](https://github.com/hashicorp/vault-secrets-operator/pull/183)
* VaultPKISecret (VPS): Ensure `Spec.AltNames`, and `Spec.IPSans`are properly formatted for the Vault request: [GH-130](https://github.com/hashicorp/vault-secrets-operator/pull/130)
* VaultPKISecret (VPS): Make `Spec.OtherSANS` a string slice (**breaking change**) : [GH-190](https://github.com/hashicorp/vault-secrets-operator/pull/190)

Features:
* VaultDynamicSecrets (VDS): CRD is extended with `Revoke` field which will result in the dynamic secret lease being revoked on rotation and CR deletion. Note: The VaultAuthMethod referenced by the VDS Secret must have a policy which provides `["update"]` on `sys/leases/revoke`. [GH-143](https://github.com/hashicorp/vault-secrets-operator/pull/143)
* VaultAuth: Adds support for the JWT authentication method which either uses the JWT token from the provided secret reference, or a service account JWT token that VSO will generate using the provided service account. [GH-131](https://github.com/hashicorp/vault-secrets-operator/pull/131)
* VaultDynamicSecrets (VDS): New `RenewalPercent` field to control when a lease is renewed [GH-170](https://github.com/hashicorp/vault-secrets-operator/pull/170)
* Helm: Support specifying extra annotations on the Operator's Deployment: [GH-169](https://github.com/hashicorp/vault-secrets-operator/pull/169)

Improvements:
* VaultDynamicSecrets (VDS): Generate new credentials if lease renewal TTL is truncated [GH-170](https://github.com/hashicorp/vault-secrets-operator/pull/170)
* VaultDynamicSecrets (VDS): Replace `Spec.Role` with `Spec.Path` (**breaking change**) [GH-172](https://github.com/hashicorp/vault-secrets-operator/pull/172)
* VaultPKISecrets (VPS): Make `commonName` optional: [GH-160](https://github.com/hashicorp/vault-secrets-operator/pull/160)
* VaultDynamicSecrets (VDS): Add support for specifying extra request params, and HTTP request method override: [GH-186](https://github.com/hashicorp/vault-secrets-operator/pull/186)
* VaultStaticSecrets (VSS): Ensure an out-of-band Secret deletion is properly remediated: [GH-137](https://github.com/hashicorp/vault-secrets-operator/pull/137)
* Honour a Vault*Secret's Vault namespace: [GH-157](https://github.com/hashicorp/vault-secrets-operator/pull/157)

## 0.1.0-beta (March 29th, 2023)

* Initial Beta Release
