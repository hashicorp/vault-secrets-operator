## Unreleased

Features:
* VaultDynamicSecrets: CRD is extended with `Revoke` field which will result in the dynamic secret lease being revoked on rotation and CR deletion. Note: The VaultAuthMethod referenced by the VDS Secret must have a policy which provides `["update"]` on `sys/leases/revoke`. [GH-143](https://github.com/hashicorp/vault-secrets-operator/pull/143)

## 0.1.0-beta (March 29th, 2023)

    * Initial Beta Release
