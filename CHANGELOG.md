## 0.4.1 (December 4th, 2023)

Improvements:
* Manager: setting `controller.manager.maxConcurrentReconciles` now applies to all Syncable Secret controllers. The previous flag for the manager `--max-concurrent-reconciles-vds` is now deprecated and replaced by `--max-concurrent-reconciles` which applies to all controllers. [GH-483](https://github.com/hashicorp/vault-secrets-operator/pull/483)

Fix:
* Helm: prefix all helper functions with `vso` to avoid subchart name collisions: [GH-487](https://github.com/hashicorp/vault-secrets-operator/pull/487)
* VSS: Ensure all resource updates are synced: [GH-492](https://github.com/hashicorp/vault-secrets-operator/pull/492)
* VDS: Fix compute static-creds rotation horizon: [GH-488](https://github.com/hashicorp/vault-secrets-operator/pull/488)

Dependency Updates:
* Bump github.com/go-jose/go-jose/v3 from 3.0.0 to 3.0.1: [GH-475](https://github.com/hashicorp/vault-secrets-operator/pull/475)
* Bump google.golang.org/api from 0.150.0 to 0.151.0: [GH-470](https://github.com/hashicorp/vault-secrets-operator/pull/470)
* Bump k8s.io/client-go from 0.28.3 to 0.28.4: [GH-469](https://github.com/hashicorp/vault-secrets-operator/pull/469)

## 0.4.0 (November 16th, 2023)

Features:
* VaultAuth: Support for the GCP authentication method when using GKE workload identity: [GH-411](https://github.com/hashicorp/vault-secrets-operator/pull/411)
* VDS: Support rotation for non-renewable secrets: [GH-397](https://github.com/hashicorp/vault-secrets-operator/pull/397)

Fix:
* Remove unneeded instantiation of the VSO ConfigMap watcher: [GH-446](https://github.com/hashicorp/vault-secrets-operator/pull/446)
* VDS: Correctly compute the lease renewal horizon after a new VSO leader has been elected and the lease is still within its renewal window: [GH-397](https://github.com/hashicorp/vault-secrets-operator/pull/397)

Dependency Updates:
* Upgrade kube-rbac-proxy to v0.15.0: [GH-458](https://github.com/hashicorp/vault-secrets-operator/pull/458)
* Bump github.com/onsi/gomega from 1.29.0 to 1.30.0: [GH-456](https://github.com/hashicorp/vault-secrets-operator/pull/456)
* Bump github.com/gruntwork-io/terratest from 0.46.5 to 0.46.6: [GH-455](https://github.com/hashicorp/vault-secrets-operator/pull/455)
* Bump google.golang.org/api from 0.149.0 to 0.150.0: [GH-454](https://github.com/hashicorp/vault-secrets-operator/pull/454)
* Bump ubi9/ubi-minimal from 9.2-750.1697625013 to 9.3-1361.1699548032: [GH-444](https://github.com/hashicorp/vault-secrets-operator/pull/444) [GH-460](https://github.com/hashicorp/vault-secrets-operator/pull/460)
* Bump ubi9/ubi-micro from 9.2-15.1696515526 to 9.3-6: [GH-443](https://github.com/hashicorp/vault-secrets-operator/pull/443)
* Bump github.com/gruntwork-io/terratest from 0.46.1 to 0.46.5: [GH-440](https://github.com/hashicorp/vault-secrets-operator/pull/440)
* Bump google.golang.org/api from 0.148.0 to 0.149.0: [GH-439](https://github.com/hashicorp/vault-secrets-operator/pull/439)
* Bump github.com/go-logr/logr from 1.2.4 to 1.3.0: [GH-435](https://github.com/hashicorp/vault-secrets-operator/pull/435)
* Bump github.com/google/uuid from 1.3.1 to 1.4.0: [GH-434](https://github.com/hashicorp/vault-secrets-operator/pull/434)
* Bump github.com/onsi/gomega from 1.28.1 to 1.29.0: [GH-433](https://github.com/hashicorp/vault-secrets-operator/pull/433)
* Bump google.golang.org/grpc from 1.57.0 to 1.57.1: [GH-428](https://github.com/hashicorp/vault-secrets-operator/pull/428)
* Bump k8s.io/apimachinery from 0.28.2 to 0.28.3: [GH-421](https://github.com/hashicorp/vault-secrets-operator/pull/421)
* Bump github.com/onsi/gomega from 1.28.0 to 1.28.1: [GH-420](https://github.com/hashicorp/vault-secrets-operator/pull/420)
* Bump k8s.io/api from 0.28.2 to 0.28.3: [GH-419](https://github.com/hashicorp/vault-secrets-operator/pull/419)
* Bump github.com/gruntwork-io/terratest from 0.46.0 to 0.46.1: [GH-418](https://github.com/hashicorp/vault-secrets-operator/pull/418)
* Bump sigs.k8s.io/controller-runtime from 0.16.2 to 0.16.3: [GH-417](https://github.com/hashicorp/vault-secrets-operator/pull/417)

## 0.3.4 (October 19th, 2023)
Fix:

* UBI image: Include the tls-ca-bundle.pem from ubi-minimal: [GH-415](https://github.com/hashicorp/vault-secrets-operator/pull/415)

## 0.3.3 (October 17th, 2023)
Fix:

* Important security update to address some Golang vulnerabilities [GH-414](https://github.com/hashicorp/vault-secrets-operator/pull/414)

Dependency Updates:
* Upgrade kube-rbac-proxy to v0.14.4 for CVE-2023-39325 [GH-414](https://github.com/hashicorp/vault-secrets-operator/pull/414)
* Bump to Go 1.21.3 for CVE-2023-39325: [GH-408](https://github.com/hashicorp/vault-secrets-operator/pull/408)
* Bump github.com/hashicorp/vault/sdk from 0.10.0 to 0.10.2: [GH-410](https://github.com/hashicorp/vault-secrets-operator/pull/410)
* Bump github.com/gruntwork-io/terratest from 0.45.0 to 0.46.0: [GH-409](https://github.com/hashicorp/vault-secrets-operator/pull/409)
* Bump golang.org/x/net from 0.14.0 to 0.17.0: [GH-407](https://github.com/hashicorp/vault-secrets-operator/pull/407)

## 0.3.2 (October 10th, 2023)
Fix:
* Handle invalid Client race after restoration: [GH-400](https://github.com/hashicorp/vault-secrets-operator/pull/400)

Dependency Updates:
* Bump ubi9/ubi-micro from 9.2-15 to 9.2-15.1696515526: [GH-404](https://github.com/hashicorp/vault-secrets-operator/pull/404)
* Bump github.com/hashicorp/hcp-sdk-go from 0.64.0 to 0.65.0: [GH-403](https://github.com/hashicorp/vault-secrets-operator/pull/403)
* Bump github.com/gruntwork-io/terratest from 0.44.0 to 0.45.0: [GH-402](https://github.com/hashicorp/vault-secrets-operator/pull/402)
* Bump github.com/prometheus/client_model from 0.4.1-0.20230718164431-9a2bf3000d16 to 0.5.0: [GH-401](https://github.com/hashicorp/vault-secrets-operator/pull/401)
* Bump github.com/go-openapi/runtime from 0.25.0 to 0.26.0: [GH-394](https://github.com/hashicorp/vault-secrets-operator/pull/394)
* Bump github.com/prometheus/client_golang from 1.16.0 to 1.17.0: [GH-393](https://github.com/hashicorp/vault-secrets-operator/pull/393)
* Bump github.com/hashicorp/golang-lru/v2 from 2.0.6 to 2.0.7: [GH-392](https://github.com/hashicorp/vault-secrets-operator/pull/392)
* Bump github.com/onsi/gomega from 1.27.10 to 1.28.0: [GH-391](https://github.com/hashicorp/vault-secrets-operator/pull/391)
* Bump github.com/hashicorp/hcp-sdk-go from 0.63.0 to 0.64.0: [GH-390](https://github.com/hashicorp/vault-secrets-operator/pull/390)

## 0.3.1 (September 27th, 2023)
Fix:
* Helm: bump the chart version and default tags to 0.3.1: [GH-386](https://github.com/hashicorp/vault-secrets-operator/pull/386)

## 0.3.0 (September 27th, 2023)

Improvements:
* VDS: Support for DB schedule-based static role rotations: [GH-369](https://github.com/hashicorp/vault-secrets-operator/pull/369)
* HVS: Rename servicePrinciple data key clientKey to clientSecret: [GH-368](https://github.com/hashicorp/vault-secrets-operator/pull/368)
* HVS: Include User-Agent and requester HTTP request headers.: [GH-382](https://github.com/hashicorp/vault-secrets-operator/pull/382)
* HVS: Add validation for spec.refreshAfter and min constraints: [GH-376](https://github.com/hashicorp/vault-secrets-operator/pull/376)
* Helm: Add support for affinity and hostAliases: [GH-343](https://github.com/hashicorp/vault-secrets-operator/pull/343)
* Helm: Add the ability to specify a security context to the deployment: [GH-289](https://github.com/hashicorp/vault-secrets-operator/pull/289)

Features:
* Add support for syncing HCP Vault Secrets: [GH-315](https://github.com/hashicorp/vault-secrets-operator/pull/315)

Revert:
* Temporarily remove/disable revoke on uninstall: [GH-383](https://github.com/hashicorp/vault-secrets-operator/pull/383) reverts [GH-202](https://github.com/hashicorp/vault-secrets-operator/pull/202)

## 0.3.0-rc.1 (September 19th, 2023)

Improvements:
* Add support for HCP Vault Secrets: [GH-315](https://github.com/hashicorp/vault-secrets-operator/pull/315)
* Add new HCPVaultSecretsApp CRD and Controller: [GH-314](https://github.com/hashicorp/vault-secrets-operator/pull/314)
* Add new HCPAuth CRD and Controller: [GH-313](https://github.com/hashicorp/vault-secrets-operator/pull/313)
* Optionally revoke and purge all cached vault clients upon Operator deployment deletion: [GH-202](https://github.com/hashicorp/vault-secrets-operator/pull/202)

## 0.2.0 (August 16th, 2023)

Improvements:
* Helm: `controller.imagePullSecrets` stanza is added to provide imagePullSecrets to the controller's containers via the serviceAccount: [GH-266](https://github.com/hashicorp/vault-secrets-operator/pull/266)
* Helm: `controller.manager.resources` values now also apply to the pre-delete-controller-cleanup-job. [GH-280](https://github.com/hashicorp/vault-secrets-operator/pull/280)
* Helm: Adding nodeselector and tolerations to deployment: [GH-272](https://github.com/hashicorp/vault-secrets-operator/pull/272)
* Helm: Add extraLabels to deployment: [#281](https://github.com/hashicorp/vault-secrets-operator/pull/281)
* Add K8s namespace support to VaultAuthRef and VaultConnectionRef: ([#291](https://github.com/hashicorp/vault-secrets-operator/pull/291))

Changes:
* Helm: Update default kube-rbac-proxy container image in helm chart from `v0.11.0` to `v0.14.1`: [GH-267](https://github.com/hashicorp/vault-secrets-operator/pull/267)
* Added Vault 1.14 and removed 1.11 from CI testing [GH-324](https://github.com/hashicorp/vault-secrets-operator/pull/324)
* K8s versions tested are now 1.23-1.27 [GH-324](https://github.com/hashicorp/vault-secrets-operator/pull/324)
* UBI-based images now built and published with releases: [GH-288](https://github.com/hashicorp/vault-secrets-operator/pull/288)
* Updated the license from MPL to Business Source License: [GH-321](https://github.com/hashicorp/vault-secrets-operator/pull/321)

Bugs:
* VaultStaticSecrets (VSS): fix issue where the response error was not being set: [GH-301](https://github.com/hashicorp/vault-secrets-operator/pull/301)

## 0.1.0 (June 12th, 2023)

Improvements:
* VaultPKISecrets (VPS): Include the CA chain (sans root) in 'tls.crt' when the destination secret type is "kubernetes.io/tls": [GH-256](https://github.com/hashicorp/vault-secrets-operator/pull/256)

Changes:
* Helm: **Breaking Change** Fix typos in values.yaml that incorrectly referenced `approle` `roleid` and `secretName` which should be `appRole` `roleId` and `secretRef` respectively under `defaultAuthMethod` and `controller.manager.clientCache.storageEncryption`: [GH-257](https://github.com/hashicorp/vault-secrets-operator/pull/257)

## 0.1.0-rc.1 (June 7th, 2023)

Features:
* Helm: Support optionally deploying the Prometheus ServiceMonitor: [GH-227](https://github.com/hashicorp/vault-secrets-operator/pull/227)
* Helm: **Breaking Change**: Adds support for additional Auth Methods in the Transit auth method template: [GH-226](https://github.com/hashicorp/vault-secrets-operator/pull/226)
  To migrate, set Kubernetes specific auth method configuration under `controller.manager.clientCache.storageEncryption`
  using the new stanza `controller.manager.clientCache.storageEncryption.kubernetes`.
* VaultAuth: Adds support for the AWS authentication method, which can use an IRSA service account, static credentials in a 
  Kubernetes secret, or the underlying node role/instance profile for authentication: [GH-235](https://github.com/hashicorp/vault-secrets-operator/pull/235)
* Helm: Add AWS to defaultAuth and storageEncryption auth: [GH-247](https://github.com/hashicorp/vault-secrets-operator/pull/247)

Improvements:
* Core: Extend vault Client validation checks to handle failed renewals: [GH-171](https://github.com/hashicorp/vault-secrets-operator/pull/171)
* VaultDynamicSecrets: Add support for synchronizing static-creds: [GH-239](https://github.com/hashicorp/vault-secrets-operator/pull/239)
* VDS: add support for drift detection for static-creds: [GH-244](https://github.com/hashicorp/vault-secrets-operator/pull/244)
* Helm: Make defaultVaultConnection.headers a map: [GH-249](https://github.com/hashicorp/vault-secrets-operator/pull/249)

Build:
* Update to go 1.20.5: [GH-248](https://github.com/hashicorp/vault-secrets-operator/pull/248)
* CI: Testing VSO in Azure K8s Service (AKS): [GH-218](https://github.com/hashicorp/vault-secrets-operator/pull/218)
* CI: Updating tests for VSO in EKS: [GH-219](https://github.com/hashicorp/vault-secrets-operator/pull/219)

Changes:
* API: Bump version from v1alpha1 to v1beta1 **Breaking Change**: [GH-251](https://github.com/hashicorp/vault-secrets-operator/pull/251)
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
