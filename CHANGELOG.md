## Unreleased

Features:
* Helm: Support optionally deploying the Prometheus ServiceMonitor: [GH-227](https://github.com/hashicorp/vault-secrets-operator/pull/227)
* Helm: **Breaking Change**: Adds support for additional Auth Methods in the Transit auth method template: [GH-226](https://github.com/hashicorp/vault-secrets-operator/pull/226)
  To migrate, set Kubernetes specific auth method configuration under `controller.manager.clientCache.storageEncryption`
  using the new stanza `controller.manager.clientCache.storageEncryption.kubernetes`.
* VaultAuth: Adds support for the AWS authentication method, which can use an IRSA service account, static credentials in a Kubernetes secret, or the underlying node role/instance profile for authentication: [GH-234](https://github.com/hashicorp/vault-secrets-operator/pull/234)

Improvements:
* Extend vault Client validation checks to handle failed renewals: [GH-171](https://github.com/hashicorp/vault-secrets-operator/pull/171)

Changes:
* VaultStaticSecrets (VSS): **Breaking Change**: Replace `Spec.Name` with `Spec.Path`: [GH-240](https://github.com/hashicorp/vault-secrets-operator/pull/240)
* VaultPKISecrets (VPS): **Breaking Change**: Replace `Spec.Name` with `Spec.Role`: [GH-233](https://github.com/hashicorp/vault-secrets-operator/pull/233)
* Helm chart: the Transit auth method kubernetes specific configuration in `controller.manager.clientCache.storageEncryption`
  has been moved to `controller.manager.clientCache.storageEncryption.kubernetes`.

## 0.1.0-beta.1 (May 25th, 2023)

Bugs:
* Helm: fix deployment templating so setting `controller.kubernetesClusterDomain` works as defined in values.yaml: [GH-183](https://github.com/hashicorp/vault-secrets-operator/pull/183)
* Helm: Add `vaultConnectionRef` to `controller.manager.clientCache.storageEncryption` for transit auth method configuration and provide a default value which uses the `default` vaultConnection. [GH-201](https://github.com/hashicorp/vault-secrets-operator/pull/201)
* VaultPKISecret (VPS): Ensure `Spec.AltNames`, and `Spec.IPSans`are properly formatted for the Vault request: [GH-130](https://github.com/hashicorp/vault-secrets-operator/pull/130)
* VaultPKISecret (VPS): Make `Spec.OtherSANS` a string slice (**breaking change**): [GH-190](https://github.com/hashicorp/vault-secrets-operator/pull/190)
* VaultConnection (VC): Ensure`Spec.CACertSecretRef` is relative to the connection's Namespace: [GH-195](https://github.com/hashicorp/vault-secrets-operator/pull/195)

Features:
* VaultDynamicSecrets (VDS): CRD is extended with `Revoke` field which will result in the dynamic secret lease being revoked on CR deletion. Note:
  The VaultAuthMethod referenced by the VDS Secret must have a policy which provides `["update"]` on `sys/leases/revoke`: [GH-143](https://github.com/hashicorp/vault-secrets-operator/pull/143) [GH-209](https://github.com/hashicorp/vault-secrets-operator/pull/209)
* VaultAuth: Adds support for the JWT authentication method which either uses the JWT token from the provided secret reference,
  or a service account JWT token that VSO will generate using the provided service account: [GH-131](https://github.com/hashicorp/vault-secrets-operator/pull/131)
* VaultDynamicSecrets (VDS): New `RenewalPercent` field to control when a lease is renewed: [GH-170](https://github.com/hashicorp/vault-secrets-operator/pull/170)
* Helm: Support specifying extra annotations on the Operator's Deployment: [GH-169](https://github.com/hashicorp/vault-secrets-operator/pull/169)

Improvements:
* VaultDynamicSecrets (VDS): Generate new credentials if lease renewal TTL is truncated: [GH-170](https://github.com/hashicorp/vault-secrets-operator/pull/170)
* VaultDynamicSecrets (VDS): Replace `Spec.Role` with `Spec.Path` (**breaking change**): [GH-172](https://github.com/hashicorp/vault-secrets-operator/pull/172)
* VaultPKISecrets (VPS): Make `commonName` optional: [GH-160](https://github.com/hashicorp/vault-secrets-operator/pull/160)
* VaultDynamicSecrets (VDS): Add support for specifying extra request params, and HTTP request method override: [GH-186](https://github.com/hashicorp/vault-secrets-operator/pull/186)
* VaultStaticSecrets (VSS): Ensure an out-of-band Secret deletion is properly remediated: [GH-137](https://github.com/hashicorp/vault-secrets-operator/pull/137)
* Honour a Vault*Secret's Vault namespace: [GH-157](https://github.com/hashicorp/vault-secrets-operator/pull/157)
* VaultStaticSecrets (VSS): Add `Spec.Version` field to support fetching a specific kv-v2 secret version: [GH-200](https://github.com/hashicorp/vault-secrets-operator/pull/200)

Changes:
* API schema (VDS): `Spec.Role` renamed to `Spec.Path` which can be set to any path supported by the
  Vault secret's engine.
* API schema (VPS): `Spec.OtherSANS` takes a slice of strings like `Spec.AltNames` and `Spec.IPSans`

## 0.1.0-beta (March 29th, 2023)

* Initial Beta Release
