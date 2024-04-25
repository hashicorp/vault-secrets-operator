## 0.6.0 (April 24th, 2024)

Fix:
* VDS: reconcile instances on lifetimeWatcher done events and other Vault client rotation events: [GH-665](https://github.com/hashicorp/vault-secrets-operator/pull/665)

Improvements:
* Core: no longer restore all clients from storage: [GH-684](https://github.com/hashicorp/vault-secrets-operator/pull/684)
* Helm: lower min k8s version to 1.21: [GH-656](https://github.com/hashicorp/vault-secrets-operator/pull/656)

Build:
* Upgrade to go 1.22.2: [GH-683](https://github.com/hashicorp/vault-secrets-operator/pull/683)
* CI: fix tests in GKE: [GH-675](https://github.com/hashicorp/vault-secrets-operator/pull/675)
* OLM: remove the `skips` from the last release: [GH-703](https://github.com/hashicorp/vault-secrets-operator/pull/703)
 
Dependency Updates:
* Bump github.com/cenkalti/backoff/v4 from 4.2.1 to 4.3.0: [GH-673](https://github.com/hashicorp/vault-secrets-operator/pull/673)
* Bump github.com/gruntwork-io/terratest from 0.46.11 to 0.46.13: [GH-669](https://github.com/hashicorp/vault-secrets-operator/pull/669)
* Bump github.com/hashicorp/go-hclog from 1.6.2 to 1.6.3: [GH-679](https://github.com/hashicorp/vault-secrets-operator/pull/679)
* Bump github.com/hashicorp/vault/api from 1.12.1 to 1.12.2: [GH-667](https://github.com/hashicorp/vault-secrets-operator/pull/667)
* Bump github.com/hashicorp/vault/sdk from 0.11.1 to 0.12.0: [GH-687](https://github.com/hashicorp/vault-secrets-operator/pull/687)
* Bump github.com/onsi/gomega from 1.32.0 to 1.33.0: [GH-696](https://github.com/hashicorp/vault-secrets-operator/pull/696)
* Bump github.com/prometheus/client_model from 0.6.0 to 0.6.1: [GH-678](https://github.com/hashicorp/vault-secrets-operator/pull/678)
* Bump google.golang.org/api from 0.171.0 to 0.172.0: [GH-672](https://github.com/hashicorp/vault-secrets-operator/pull/672)
* Bump k8s.io/client-go from 0.29.2 to 0.29.3: [GH-660](https://github.com/hashicorp/vault-secrets-operator/pull/660)
* Bump sigs.k8s.io/controller-runtime from 0.17.2 to 0.17.3: [GH-688](https://github.com/hashicorp/vault-secrets-operator/pull/688)

## 0.5.2 (March 13th, 2024)

Improvements:
* VDS: support configuring an explicit sync delay for non-renewable leases without an explicit TTL: [GH-641](https://github.com/hashicorp/vault-secrets-operator/pull/641)
* OLM: add newly required ClusterServiceVersion annotations: [GH-628](https://github.com/hashicorp/vault-secrets-operator/pull/628)
* Helm: mention global transformation option env variable: [GH-626](https://github.com/hashicorp/vault-secrets-operator/pull/626)

Fix:
* API: make some required bool parameters optional: [GH-650](https://github.com/hashicorp/vault-secrets-operator/pull/650)
* VDS: make rotationSchedule status field optional: [GH-621](https://github.com/hashicorp/vault-secrets-operator/pull/621)
* VPS: return an error when the PKI secret is nil: [GH-636](https://github.com/hashicorp/vault-secrets-operator/pull/636)
* Core: ensure VaultConnection headers are set on the vault client: [GH-629](https://github.com/hashicorp/vault-secrets-operator/pull/629)

Build:
* Use Go 1.21.8: [GH-651](https://github.com/hashicorp/vault-secrets-operator/pull/651)

Dependency Updates:
* Bump github.com/go-jose/go-jose/v3 from 3.0.1 to 3.0.3: [GH-646](https://github.com/hashicorp/vault-secrets-operator/pull/646)
* Bump github.com/go-openapi/runtime from 0.27.1 to 0.28.0: [GH-648](https://github.com/hashicorp/vault-secrets-operator/pull/648)
* Bump github.com/go-openapi/strfmt from 0.22.1 to 0.23.0: [GH-649](https://github.com/hashicorp/vault-secrets-operator/pull/649)
* Bump github.com/prometheus/client_golang from 1.18.0 to 1.19.0: [GH-634](https://github.com/hashicorp/vault-secrets-operator/pull/634)
* Bump github.com/stretchr/testify from 1.8.4 to 1.9.0: [GH-633](https://github.com/hashicorp/vault-secrets-operator/pull/633)
* Bump google.golang.org/api from 0.167.0 to 0.169.0: [GH-647](https://github.com/hashicorp/vault-secrets-operator/pull/647)
* Bump google.golang.org/protobuf from 1.32.0 to 1.33.0: [GH-642](https://github.com/hashicorp/vault-secrets-operator/pull/642)
* Bump sigs.k8s.io/controller-runtime from 0.17.1 to 0.17.2: [GH-625](https://github.com/hashicorp/vault-secrets-operator/pull/625)
* Bump ubi9/ubi-micro from 9.3-13 to 9.3-15: [GH-640](https://github.com/hashicorp/vault-secrets-operator/pull/640)
* Bump ubi9/ubi-minimal from 9.3-1552 to 9.3-1612: [GH-639](https://github.com/hashicorp/vault-secrets-operator/pull/639)

## 0.5.1 (February 20th, 2024)

Fix:
* Sync: mitigate potential schema validation failures by only adding finalizers after a status update: [GH-609](https://github.com/hashicorp/vault-secrets-operator/pull/609)

Dependency Updates:
* Bump github.com/prometheus/client_model from 0.5.0 to 0.6.0: [GH-613](https://github.com/hashicorp/vault-secrets-operator/pull/613)
* Bump google.golang.org/api from 0.163.0 to 0.165.0: [GH-614](https://github.com/hashicorp/vault-secrets-operator/pull/614)
* Bump k8s.io/api from 0.29.1 to 0.29.2: [GH-612](https://github.com/hashicorp/vault-secrets-operator/pull/612)
* Bump k8s.io/apimachinery from 0.29.1 to 0.29.2: [GH-615](https://github.com/hashicorp/vault-secrets-operator/pull/615)
* Bump k8s.io/client-go from 0.29.1 to 0.29.2: [GH-611](https://github.com/hashicorp/vault-secrets-operator/pull/611)

## 0.5.0 (February 15th, 2024)

KNOWN ISSUES:
* Upgrades via OperatorHub may fail due to some new required fields in VaultConnection and the Secret types as described in [GH-631](https://github.com/hashicorp/vault-secrets-operator/issues/631)

Features:
* Sync: add support for secret data transformation: [GH-437](https://github.com/hashicorp/vault-secrets-operator/pull/437)

Improvements:
* Core: set CLI options from VSO_ environment variables: [GH-551](https://github.com/hashicorp/vault-secrets-operator/pull/551)
* Sync: Reconcile on secret deletion: [GH-587](https://github.com/hashicorp/vault-secrets-operator/pull/587)
* Sync: support excluding _raw from the destination: [GH-546](https://github.com/hashicorp/vault-secrets-operator/pull/546)
* Sync: take ownership of an existing destination secret: [GH-545](https://github.com/hashicorp/vault-secrets-operator/pull/545)
* Sync: add support for userIDs in VaultPKISecret: [GH-552](https://github.com/hashicorp/vault-secrets-operator/pull/552)
* OLM: set OLM bundle to "Seamless Upgrades": [GH-581](https://github.com/hashicorp/vault-secrets-operator/pull/581)
* Helm: add annotations to the cleanup job: [GH-284](https://github.com/hashicorp/vault-secrets-operator/pull/284)
* Helm: support setting imagePullPolicy: [GH-601](https://github.com/hashicorp/vault-secrets-operator/pull/601)
* Helm: support setting VaultAuth allowedNamespaces: [GH-602](https://github.com/hashicorp/vault-secrets-operator/pull/602)

Fix:
* Sync: sync HCPVaultSecretsApp on lastGeneration change: [GH-591](https://github.com/hashicorp/vault-secrets-operator/pull/591)
* Sync: properly handle secret type changes: [GH-605](https://github.com/hashicorp/vault-secrets-operator/pull/605)

Build:
* Install the operator-sdk CLI and check `sdk-generate` in CI: [GH-590](https://github.com/hashicorp/vault-secrets-operator/pull/590)
* Bump some GH action versions: [GH-583](https://github.com/hashicorp/vault-secrets-operator/pull/583)

Dependency Updates:
* Bump github.com/go-openapi/runtime from 0.26.2 to 0.27.1: [GH-572](https://github.com/hashicorp/vault-secrets-operator/pull/572)
* Bump github.com/google/uuid from 1.5.0 to 1.6.0: [GH-570](https://github.com/hashicorp/vault-secrets-operator/pull/570)
* Bump github.com/gruntwork-io/terratest from 0.46.8 to 0.46.11: [GH-550](https://github.com/hashicorp/vault-secrets-operator/pull/550)
* Bump github.com/hashicorp/go-secure-stdlib/awsutil from 0.2.3-0.20230606170242-1a4b95565d57 to 0.3.0: [GH-579](https://github.com/hashicorp/vault-secrets-operator/pull/579)
* Bump github.com/hashicorp/vault/api from 1.11.0 to 1.12.0: [GH-595](https://github.com/hashicorp/vault-secrets-operator/pull/595)
* Bump github.com/hashicorp/vault/sdk from 0.10.2 to 0.11.0: [GH-596](https://github.com/hashicorp/vault-secrets-operator/pull/596)
* Bump github.com/onsi/gomega from 1.30.0 to 1.31.1: [GH-558](https://github.com/hashicorp/vault-secrets-operator/pull/558)
* Bump google.golang.org/api from 0.161.0 to 0.163.0: [GH-594](https://github.com/hashicorp/vault-secrets-operator/pull/594)
* Bump k8s.io/api from 0.29.0 to 0.29.1: [GH-556](https://github.com/hashicorp/vault-secrets-operator/pull/556)
* Bump k8s.io/client-go from 0.29.0 to 0.29.1: [GH-554](https://github.com/hashicorp/vault-secrets-operator/pull/554)
* Bump sigs.k8s.io/controller-runtime from 0.17.0 to 0.17.1: [GH-597](https://github.com/hashicorp/vault-secrets-operator/pull/597)
* Bump ubi9/ubi-micro from 9.3-9 to 9.3-13: [GH-566](https://github.com/hashicorp/vault-secrets-operator/pull/566)
* Bump ubi9/ubi-minimal from 9.3-1475 to 9.3-1552: [GH-565](https://github.com/hashicorp/vault-secrets-operator/pull/565)

## 0.4.3 (January 10th, 2024)

Fix:
* Helm: rename and truncate the pre-delete cleanup job to 63 characters: [GH-506](https://github.com/hashicorp/vault-secrets-operator/pull/506)
* VDS: remediate deleted destination secret: [GH-532](https://github.com/hashicorp/vault-secrets-operator/pull/532)
* Update paused deployment error message: [GH-528](https://github.com/hashicorp/vault-secrets-operator/pull/528)
* VC: provide default value for spec.skipTLSVerify: [GH-527](https://github.com/hashicorp/vault-secrets-operator/pull/527)
* CCS: ensure invalid storage objects are deleted: [GH-525](https://github.com/hashicorp/vault-secrets-operator/pull/525)
* VDS: Log and record Vault request failures: [GH-508](https://github.com/hashicorp/vault-secrets-operator/pull/508)
* VPS: Sync on any update: [GH-479](https://github.com/hashicorp/vault-secrets-operator/pull/479)

Dependency Updates:
* update go version to fix CVE-2023-45284,CVE-2023-39326,CVE-2023-48795: [GH-541](https://github.com/hashicorp/vault-secrets-operator/pull/541)
* Bump google.golang.org/api from 0.154.0 to 0.155.0: [GH-542](https://github.com/hashicorp/vault-secrets-operator/pull/542)
* Bump github.com/prometheus/client_golang from 1.17.0 to 1.18.0: [GH-540](https://github.com/hashicorp/vault-secrets-operator/pull/540)
* Bump github.com/go-openapi/strfmt from 0.21.9 to 0.22.0: [GH-539](https://github.com/hashicorp/vault-secrets-operator/pull/539)
* Bump github.com/go-logr/logr from 1.3.0 to 1.4.1: [GH-536](https://github.com/hashicorp/vault-secrets-operator/pull/536)
* Bump golang.org/x/crypto from 0.16.0 to 0.17.0: [GH-524](https://github.com/hashicorp/vault-secrets-operator/pull/524)
* Bump k8s.io/client-go from 0.28.4 to 0.29.0: [GH-523](https://github.com/hashicorp/vault-secrets-operator/pull/523)
* Bump google.golang.org/api from 0.153.0 to 0.154.0: [GH-522](https://github.com/hashicorp/vault-secrets-operator/pull/522)
* Bump github.com/hashicorp/go-hclog from 1.6.1 to 1.6.2: [GH-521](https://github.com/hashicorp/vault-secrets-operator/pull/521)
* Bump github.com/google/uuid from 1.4.0 to 1.5.0: [GH-520](https://github.com/hashicorp/vault-secrets-operator/pull/520)
* Bump ubi9/ubi-minimal from 9.3-1361.1699548032 to 9.3-1475: [GH-516](https://github.com/hashicorp/vault-secrets-operator/pull/516)
* Bump ubi9/ubi-micro from 9.3-6 to 9.3-9: [GH-515](https://github.com/hashicorp/vault-secrets-operator/pull/515)
* Bump github.com/go-openapi/strfmt from 0.21.8 to 0.21.9: [GH-514](https://github.com/hashicorp/vault-secrets-operator/pull/514)
* Bump github.com/hashicorp/go-hclog from 1.5.0 to 1.6.1: [GH-513](https://github.com/hashicorp/vault-secrets-operator/pull/513)
* Bump github.com/go-openapi/runtime from 0.26.0 to 0.26.2: [GH-512](https://github.com/hashicorp/vault-secrets-operator/pull/512)
* Bump github.com/gruntwork-io/terratest from 0.46.6 to 0.46.8: [GH-497](https://github.com/hashicorp/vault-secrets-operator/pull/497)
* Bump google.golang.org/api from 0.152.0 to 0.153.0: [GH-496](https://github.com/hashicorp/vault-secrets-operator/pull/496)

## 0.4.2 (December 7th, 2023)

Fix:
* Include viewer and editor RBAC roles in the chart: [GH-501](https://github.com/hashicorp/vault-secrets-operator/pull/501)
* Build: image/ubi: add separate target and build job for RedHat: [GH-503](https://github.com/hashicorp/vault-secrets-operator/pull/503)

Dependency Updates:
* Bump github.com/go-openapi/strfmt from 0.21.7 to 0.21.8: [GH-490](https://github.com/hashicorp/vault-secrets-operator/pull/490)
* Bump google.golang.org/api from 0.151.0 to 0.152.0: [GH-489](https://github.com/hashicorp/vault-secrets-operator/pull/489)

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
