## 1.1.0 (December 12th, 2025)

Enhancements:
* Add support for linux/s390x and linux/arm64 (Red Hat): ([#1152](https://github.com/hashicorp/vault-secrets-operator/pull/1152))

Fixes:
* Topology spread constraints bugfix: ([#1148](https://github.com/hashicorp/vault-secrets-operator/pull/1148))
* Update docs branch version: ([#1140](https://github.com/hashicorp/vault-secrets-operator/pull/1140))

Build:
* ci: updating vault-helm to v0.31.0 and latest Vault versions: ([#1125](https://github.com/hashicorp/vault-secrets-operator/pull/1125))

Dependency Updates:
* Bump the gomod-backward-compatible group across 1 directory with 4 updates: ([#1172](https://github.com/hashicorp/vault-secrets-operator/pull/1172))
* Bump the gomod-backward-compatible group with 4 updates: ([#1178](https://github.com/hashicorp/vault-secrets-operator/pull/1178))
* Bump github.com/gruntwork-io/terratest from 0.53.0 to 0.54.0 in the gomod-backward-compatible group: ([#1162](https://github.com/hashicorp/vault-secrets-operator/pull/1162))
* Bump the gomod-backward-compatible group across 1 directory with 6 updates: ([#1147](https://github.com/hashicorp/vault-secrets-operator/pull/1147))
* Bump golang.org/x/crypto from 0.43.0 to 0.45.0: ([#1154](https://github.com/hashicorp/vault-secrets-operator/pull/1154))
* Bump the gomod-backward-compatible group with 7 updates: ([#1157](https://github.com/hashicorp/vault-secrets-operator/pull/1157))
* Bump google.golang.org/api from 0.250.0 to 0.251.0 in the gomod-backward-compatible group: ([#1133](https://github.com/hashicorp/vault-secrets-operator/pull/1133))
* Bump the gomod-backward-compatible group with 5 updates: ([#1128](https://github.com/hashicorp/vault-secrets-operator/pull/1128))
* Bump Go version to 1.25.4: ([#1151](https://github.com/hashicorp/vault-secrets-operator/pull/1151))
* Bump ubi10/ubi-micro from 10.0 to 10.1: ([#1150](https://github.com/hashicorp/vault-secrets-operator/pull/1150))
* Bump ubi10/ubi-minimal from 10.0 to 10.1: ([#1149](https://github.com/hashicorp/vault-secrets-operator/pull/1149))

## 1.0.1 (September 26th, 2025)

Fix:
* VSS: rollout restarts were being executed erroneously [GH-1126](https://github.com/hashicorp/vault-secrets-operator/pull/1126)


## 1.0.0 (September 24th, 2025)
Features:
* Add support for the VSO CSI Driver (Vault Enterprise only): [GH-1098](https://github.com/hashicorp/vault-secrets-operator/pull/1098)

Enhancements:
* Helm: update values comment: [GH-1046](https://github.com/hashicorp/vault-secrets-operator/pull/1046)
* Helm: Support setting priorityClassName, topologySpreadConstraints and podDisruptionBudget: [GH-1050](https://github.com/hashicorp/vault-secrets-operator/pull/1050)
* API: Include conditions on supported types: [GH-1058](https://github.com/hashicorp/vault-secrets-operator/pull/1058)
* API: Clarify VaultAuth allowedNamespaces docs: [GH-1113](https://github.com/hashicorp/vault-secrets-operator/pull/1113)

Fix:
* No longer store non-renewable Vault clients: [GH-1066](https://github.com/hashicorp/vault-secrets-operator/pull/1066)

Build:
* CI: Add scale tests: [GH-916](https://github.com/hashicorp/vault-secrets-operator/pull/916)
* CI: update k8s and vault versions: [GH-1033](https://github.com/hashicorp/vault-secrets-operator/pull/1033)
* SEC-090: Automated trusted workflow pinning (2025-03-24): [GH-1038](https://github.com/hashicorp/vault-secrets-operator/pull/1038)
* CI: Add v0.9.1 and v0.10.0 to chart upgrade tests: [GH-1039](https://github.com/hashicorp/vault-secrets-operator/pull/1039)
* SEC-090: Automated trusted workflow pinning (2025-03-31): [GH-1042](https://github.com/hashicorp/vault-secrets-operator/pull/1042)
* CI: disable HVS integration tests.: [GH-1090](https://github.com/hashicorp/vault-secrets-operator/pull/1090)
* CI: Update k8s and vault versions: [GH-1105](https://github.com/hashicorp/vault-secrets-operator/pull/1105)
* [Compliance] - PR Template Changes Required: [GH-1086](https://github.com/hashicorp/vault-secrets-operator/pull/1086)
* CI: Give the VDS reconciliation check a bit more time.: [GH-1114](https://github.com/hashicorp/vault-secrets-operator/pull/1114)
* CI: Standardize security-scanner config and update Go version: [GH-1080](https://github.com/hashicorp/vault-secrets-operator/pull/1080)
* Add CSI containers to check-versions script: [GH-1116](https://github.com/hashicorp/vault-secrets-operator/pull/1116)

Dependency Updates:
* Bump golang.org/x/net from 0.35.0 to 0.36.0: [GH-1031](https://github.com/hashicorp/vault-secrets-operator/pull/1031)
* Bump the gomod-backward-compatible group across 1 directory with 10 updates: [GH-1037](https://github.com/hashicorp/vault-secrets-operator/pull/1037)
* Bump the gomod-backward-compatible group across 1 directory with 4 updates: [GH-1048](https://github.com/hashicorp/vault-secrets-operator/pull/1048)
* Bump golang.org/x/net from 0.37.0 to 0.38.0: [GH-1052](https://github.com/hashicorp/vault-secrets-operator/pull/1052)
* Bump the gomod-backward-compatible group across 1 directory with 9 updates: [GH-1065](https://github.com/hashicorp/vault-secrets-operator/pull/1065)
* Bump ubi9/ubi-micro from 9.5 to 9.6: [GH-1067](https://github.com/hashicorp/vault-secrets-operator/pull/1067)
* Bump ubi9/ubi-minimal from 9.5 to 9.6: [GH-1068](https://github.com/hashicorp/vault-secrets-operator/pull/1068)
* Bump the gomod-backward-compatible group across 1 directory with 11 updates: [GH-1083](https://github.com/hashicorp/vault-secrets-operator/pull/1083)
* Bump the gomod-backward-compatible group across 1 directory with 8 updates: [GH-1089](https://github.com/hashicorp/vault-secrets-operator/pull/1089)
* Bump the gomod-backward-compatible group across 1 directory with 8 updates: [GH-1095](https://github.com/hashicorp/vault-secrets-operator/pull/1095)
* Bump github.com/ulikunitz/xz from 0.5.10 to 0.5.14: [GH-1102](https://github.com/hashicorp/vault-secrets-operator/pull/1102)
* Bump go version to 1.24.7: [GH-1108](https://github.com/hashicorp/vault-secrets-operator/pull/1108)
* Bump the gomod-backward-compatible group across 1 directory with 9 updates: [GH-1110](https://github.com/hashicorp/vault-secrets-operator/pull/1110)
* Upgrade to ubi10: [GH-1111](https://github.com/hashicorp/vault-secrets-operator/pull/1111)
* Bump the gomod-backward-compatible group with 7 updates: [GH-1112](https://github.com/hashicorp/vault-secrets-operator/pull/1112)
* Bump cloud.google.com/go/compute/metadata from 0.8.0 to 0.8.4: [GH-1117](https://github.com/hashicorp/vault-secrets-operator/pull/1117)
* Bump argorollouts to v1.8.3: [GH-1119](https://github.com/hashicorp/vault-secrets-operator/pull/1119)


## 0.10.0 (March 4th, 2025)

Enhancements:
* Add Kubernetes Client QPS and Burst Configuration: [GH-1013](https://github.com/hashicorp/vault-secrets-operator/pull/1013)

Fix:
* Add new Client for caching VSO owned Secrets: [GH-1010](https://github.com/hashicorp/vault-secrets-operator/pull/1010)
* VPS: support day duration notation for TTL: [GH-990](https://github.com/hashicorp/vault-secrets-operator/pull/990)

Build:
* Build with Go 1.23.6: [GH-1024](https://github.com/hashicorp/vault-secrets-operator/pull/1024)
* SEC-090: Automated trusted workflow pinning (2024-12-23): [GH-993](https://github.com/hashicorp/vault-secrets-operator/pull/993)
* SEC-090: Automated trusted workflow pinning (2024-12-30): [GH-995](https://github.com/hashicorp/vault-secrets-operator/pull/995)
* SEC-090: Automated trusted workflow pinning (2025-01-07): [GH-997](https://github.com/hashicorp/vault-secrets-operator/pull/997)
* SEC-090: Automated trusted workflow pinning (2025-01-20): [GH-1005](https://github.com/hashicorp/vault-secrets-operator/pull/1005)
* SEC-090: Automated trusted workflow pinning (2025-02-03): [GH-1009](https://github.com/hashicorp/vault-secrets-operator/pull/1009)
* SEC-090: Automated trusted workflow pinning (2025-02-10): [GH-1012](https://github.com/hashicorp/vault-secrets-operator/pull/1012)
* SEC-090: Automated trusted workflow pinning (2025-02-17): [GH-1015](https://github.com/hashicorp/vault-secrets-operator/pull/1015)

Dependency Updates:
* Bump github.com/go-jose/go-jose/v4 from 4.0.1 to 4.0.5: [GH-1020](https://github.com/hashicorp/vault-secrets-operator/pull/1020)
* Bump the gomod-backward-compatible group across 1 directory with 3 updates: [GH-994](https://github.com/hashicorp/vault-secrets-operator/pull/994)
* Bump the gomod-backward-compatible group across 1 directory with 8 updates: [GH-1014](https://github.com/hashicorp/vault-secrets-operator/pull/1014)
* Bump the gomod-backward-compatible group across 1 directory with 9 updates: [GH-988](https://github.com/hashicorp/vault-secrets-operator/pull/988)
* Bump the gomod-backward-compatible group with 2 updates: [GH-1007](https://github.com/hashicorp/vault-secrets-operator/pull/1007)
* Bump the gomod-backward-compatible group with 3 updates: [GH-1001](https://github.com/hashicorp/vault-secrets-operator/pull/1001)
* Bump the gomod-backward-compatible group with 3 updates: [GH-1018](https://github.com/hashicorp/vault-secrets-operator/pull/1018)
* Bump the gomod-backward-compatible group with 6 updates: [GH-989](https://github.com/hashicorp/vault-secrets-operator/pull/989)
* Bump the gomod-backward-compatible group with 7 updates: [GH-1004](https://github.com/hashicorp/vault-secrets-operator/pull/1004)
* Bump golang.org/x/crypto from v0.34.0 to v0.35.0 [GH-1024](https://github.com/hashicorp/vault-secrets-operator/pull/1024)


## 0.9.1 (December 11th, 2024)

Fix:
* Memory: Prevent OOM due to large K8s Secrets cache: [GH-982](https://github.com/hashicorp/vault-secrets-operator/pull/982) [GH-984](https://github.com/hashicorp/vault-secrets-operator/pull/984)

Improvements:
* add events for HVS client failures: [GH-960](https://github.com/hashicorp/vault-secrets-operator/pull/960)
* Memory: Use the mutex pool provided by K8s keymutex: [GH-975](https://github.com/hashicorp/vault-secrets-operator/pull/975)

Build:
* SEC-090: Automated trusted workflow pinning (2024-10-28): [GH-957](https://github.com/hashicorp/vault-secrets-operator/pull/957)
* Bump K8s version: [GH-968](https://github.com/hashicorp/vault-secrets-operator/pull/968)

Dependency Updates:
* Bump the gomod-backward-compatible group with 2 updates: [GH-950](https://github.com/hashicorp/vault-secrets-operator/pull/950)
* Bump the gomod-backward-compatible group across 1 directory with 9 updates: [GH-958](https://github.com/hashicorp/vault-secrets-operator/pull/958)
* Bump ubi9/ubi-micro from 9.4-15 to 9.5: [GH-970](https://github.com/hashicorp/vault-secrets-operator/pull/970)
* Bump ubi9/ubi-minimal from 9.4-1227.1726694542 to 9.5: [GH-971](https://github.com/hashicorp/vault-secrets-operator/pull/971)
* Bump golang.org/x/crypto from 0.28.0 to 0.31.0: [GH-987](https://github.com/hashicorp/vault-secrets-operator/pull/987)


## 0.9.0 (October 8th, 2024)

Features:
* Add support for syncing [HVS rotating secrets](https://developer.hashicorp.com/hcp/docs/vault-secrets/auto-rotation): [GH-893](https://github.com/hashicorp/vault-secrets-operator/pull/893) [GH-889](https://github.com/hashicorp/vault-secrets-operator/pull/889)
* Add support for syncing [HVS dynamic secrets](https://developer.hashicorp.com/hcp/docs/vault-secrets/dynamic-secrets): [GH-917](https://github.com/hashicorp/vault-secrets-operator/pull/917) [GH-939](https://github.com/hashicorp/vault-secrets-operator/pull/939) [GH-934](https://github.com/hashicorp/vault-secrets-operator/pull/934) [GH-941](https://github.com/hashicorp/vault-secrets-operator/pull/941)

Fix:
* VC: update `spec.timeout` to be a string: [GH-906](https://github.com/hashicorp/vault-secrets-operator/pull/906)

Improvements:
* VSS(instant-updates): more stable event watcher: [GH-898](https://github.com/hashicorp/vault-secrets-operator/pull/898)
* Bump kube-rbac-proxy to 0.18.1: [GH-909](https://github.com/hashicorp/vault-secrets-operator/pull/909)

Build:
* Upgrade controller-gen to 0.16.3: [GH-944](https://github.com/hashicorp/vault-secrets-operator/pull/944)
* SEC-090: Automated trusted workflow pinning (2024-08-13): [GH-888](https://github.com/hashicorp/vault-secrets-operator/pull/888)
* SEC-090: Automated trusted workflow pinning (2024-08-19): [GH-897](https://github.com/hashicorp/vault-secrets-operator/pull/897)
* SEC-090: Automated trusted workflow pinning (2024-09-30): [GH-937](https://github.com/hashicorp/vault-secrets-operator/pull/937)
* Use dependabot groups for Go deps: [GH-924](https://github.com/hashicorp/vault-secrets-operator/pull/924)
* Conform to IPS-002: [GH-947](https://github.com/hashicorp/vault-secrets-operator/pull/947)

Dependency Updates:
* Bump the gomod-backward-compatible group across 1 directory with 14 updates: [GH-943](https://github.com/hashicorp/vault-secrets-operator/pull/943)
* Bump golang.org/x/crypto from 0.27.0 to 0.28.0 in the gomod-backward-compatible group: [GH-945](https://github.com/hashicorp/vault-secrets-operator/pull/945)
* Bump ubi9/ubi-micro from 9.4-13 to 9.4-15: [GH-904](https://github.com/hashicorp/vault-secrets-operator/pull/904)
* Bump ubi9/ubi-minimal from 9.4-1227.1725849298 to 9.4-1227.1726694542: [GH-930](https://github.com/hashicorp/vault-secrets-operator/pull/930)


## 0.8.1 (July 29th, 2024)

Improvements:
* Log build info on startup: [GH-872](https://github.com/hashicorp/vault-secrets-operator/pull/872)
* API: Support setting the Vault request timeout on a VaultConnection: [GH-862](https://github.com/hashicorp/vault-secrets-operator/pull/862)

Fix:
* Fix: encryption client deadlocking the factory: [GH-868](https://github.com/hashicorp/vault-secrets-operator/pull/868)
* Helm(hooks): honor imagePullPolicy and imagePullSecrets: [GH-873](https://github.com/hashicorp/vault-secrets-operator/pull/873)

Build:
* SEC-090: Automated trusted workflow pinning (2024-07-22): [GH-866](https://github.com/hashicorp/vault-secrets-operator/pull/866)
* SEC-090: Automated trusted workflow pinning (2024-07-17): [GH-859](https://github.com/hashicorp/vault-secrets-operator/pull/859)

Dependency Updates:
* Bump github.com/onsi/gomega from 1.33.1 to 1.34.0: [GH-874](https://github.com/hashicorp/vault-secrets-operator/pull/874)
* Bump google.golang.org/api from 0.188.0 to 0.189.0: [GH-875](https://github.com/hashicorp/vault-secrets-operator/pull/875)
* Bump k8s.io/apiextensions-apiserver from 0.30.2 to 0.30.3: [GH-864](https://github.com/hashicorp/vault-secrets-operator/pull/864)
* Bump k8s.io/client-go from 0.30.2 to 0.30.3: [GH-865](https://github.com/hashicorp/vault-secrets-operator/pull/865)
* Bump ubi9/ubi-micro from 9.4-9 to 9.4-13: [GH-870](https://github.com/hashicorp/vault-secrets-operator/pull/870)
* Bump ubi9/ubi-minimal from 9.4-1134 to 9.4-1194: [GH-869](https://github.com/hashicorp/vault-secrets-operator/pull/869)


## 0.8.0 (July 18th, 2024)
**Important**

* Helm: CRD schema changes are now automatically applied at upgrade time.
 
  *See [updating-crds](https://developer.hashicorp.com/vault/docs/platform/k8s/vso/installation#updating-crds-when-using-helm) for more details.*

* This release contains CRD schema changes which remove the field validation on most VaultAuth spec fields. That means invalid VaultAuth
  configurations will no longer be handled at resource application time. Please review the VSO logs and K8s
  events when troubleshooting Vault authentication issues.

Features:
* Helm: add support for auto upgrading CRDs: [GH-789](https://github.com/hashicorp/vault-secrets-operator/pull/789)
* VaultStaticSecret: support [instant event-driven updates](https://developer.hashicorp.com/vault/docs/platform/k8s/vso/sources/vault#instant-updates): [GH-771](https://github.com/hashicorp/vault-secrets-operator/pull/771)
* Add new [VaultAuthGlobal](https://developer.hashicorp.com/vault/docs/platform/k8s/vso/sources/vault#vaultauthglobal-custom-resource) type for shared VaultAuth configurations: 
 [GH-735](https://github.com/hashicorp/vault-secrets-operator/pull/735)
 [GH-800](https://github.com/hashicorp/vault-secrets-operator/pull/800)
 [GH-847](https://github.com/hashicorp/vault-secrets-operator/pull/847)
 [GH-855](https://github.com/hashicorp/vault-secrets-operator/pull/855)
 [GH-850](https://github.com/hashicorp/vault-secrets-operator/pull/850)
* CachingClientFactory: support client taints to trigger Vault client token validation: 
  [GH-717](https://github.com/hashicorp/vault-secrets-operator/pull/717)
  [GH-769](https://github.com/hashicorp/vault-secrets-operator/pull/769)

Improvements:
* VPS: add ca.crt from issuing CA for tls secret type: [GH-848](https://github.com/hashicorp/vault-secrets-operator/pull/848)
* Helm: support setting VaultAuthGlobalRef on VaultAuth: [GH-851](https://github.com/hashicorp/vault-secrets-operator/pull/851)
* Migrate to k8s.io/utils/ptr: [GH-856](https://github.com/hashicorp/vault-secrets-operator/pull/856)
* Core: update backoff option docs: [GH-801](https://github.com/hashicorp/vault-secrets-operator/pull/801)
 
Fix:
* VaultAuth: set valid status on VaultAuthGlobal deref error: [GH-854](https://github.com/hashicorp/vault-secrets-operator/pull/854)
* VDS: properly handle the clone cache key variant during client callback execution: [GH-835](https://github.com/hashicorp/vault-secrets-operator/pull/835)
* Core: delete resource status metrics upon object deletion: [GH-815](https://github.com/hashicorp/vault-secrets-operator/pull/815)
* VSS: use a constant backoff on some reconciliation errors: [GH-811](https://github.com/hashicorp/vault-secrets-operator/pull/811)
* VDS: work around Vault DB static creds TTL rollover bug: [GH-730](https://github.com/hashicorp/vault-secrets-operator/pull/730)

Build:
* CI: bump Vault versions: [GH-797](https://github.com/hashicorp/vault-secrets-operator/pull/797)

Dependency Updates:
* Bump cloud.google.com/go/compute/metadata from 0.4.0 to 0.5.0: [GH-853](https://github.com/hashicorp/vault-secrets-operator/pull/853)
* Bump github.com/gruntwork-io/terratest from 0.46.16 to 0.47.0: [GH-852](https://github.com/hashicorp/vault-secrets-operator/pull/852)
* Bump github.com/hashicorp/go-getter from 1.7.4 to 1.7.5: [GH-834](https://github.com/hashicorp/vault-secrets-operator/pull/834)
* Bump github.com/hashicorp/go-retryablehttp from 0.7.1 to 0.7.7: [GH-833](https://github.com/hashicorp/vault-secrets-operator/pull/833)
* Bump github.com/hashicorp/go-version from 1.6.0 to 1.7.0: [GH-810](https://github.com/hashicorp/vault-secrets-operator/pull/810)
* Bump golang.org/x/crypto from 0.24.0 to 0.25.0: [GH-843](https://github.com/hashicorp/vault-secrets-operator/pull/843)
* Bump google.golang.org/api from 0.186.0 to 0.188.0: [GH-846](https://github.com/hashicorp/vault-secrets-operator/pull/846)
* Bump google.golang.org/grpc from 1.64.0 to 1.64.1: [GH-845](https://github.com/hashicorp/vault-secrets-operator/pull/845)
* Bump k8s.io/api from 0.30.1 to 0.30.2: [GH-822](https://github.com/hashicorp/vault-secrets-operator/pull/822)
* Bump k8s.io/apiextensions-apiserver from 0.30.1 to 0.30.2: [GH-828](https://github.com/hashicorp/vault-secrets-operator/pull/828)
* Bump k8s.io/client-go from 0.30.1 to 0.30.2: [GH-830](https://github.com/hashicorp/vault-secrets-operator/pull/830)
* Bump sigs.k8s.io/controller-runtime from 0.18.3 to 0.18.4: [GH-808](https://github.com/hashicorp/vault-secrets-operator/pull/808)
* Bump ubi9/ubi-micro from 9.4-6.1716471860 to 9.4-9: [GH-819](https://github.com/hashicorp/vault-secrets-operator/pull/819)
* Bump ubi9/ubi-minimal from 9.4-949.1717074713 to 9.4-1134: [GH-820](https://github.com/hashicorp/vault-secrets-operator/pull/820)


## 0.7.1 (May 30th, 2024)

Fix:
* Helm: fix invalid value name for telemetry.serviceMonitor.enabled (#786): [GH-790](https://github.com/hashicorp/vault-secrets-operator/pull/790)


## 0.7.0 (May 27th, 2024)
**Important**: this release contains CRD schema changes that must be applied manually when deploying VSO with Helm. 
Please see [updating-crds](https://developer.hashicorp.com/vault/docs/platform/k8s/vso/installation#updating-crds-when-using-helm) for more details.

Behavioral changes:
* Core: Controller logs are now JSON encoded by default.

Features:
* Core: support argo.Rollout as a rolloutRestartTarget for all secret type custom resources: [GH-702](https://github.com/hashicorp/vault-secrets-operator/pull/702)
* Helm: add support for cluster role aggregates: [GH-752](https://github.com/hashicorp/vault-secrets-operator/pull/752)
* Helm: adds values for setting VSO logging options: [GH-778](https://github.com/hashicorp/vault-secrets-operator/pull/778)
* Helm: add support for configuring strategy on controller deployment : [GH-709](https://github.com/hashicorp/vault-secrets-operator/pull/709)

Improvements:
* CachingClientFactory: lock by client cache key: [GH-716](https://github.com/hashicorp/vault-secrets-operator/pull/716)
* Transformations: add support for the htpasswd Sprig function: [GH-708](https://github.com/hashicorp/vault-secrets-operator/pull/708)
* VPS: skip overwriting tls.crt and tls.key whenever transformation templates are configured: [GH-659](https://github.com/hashicorp/vault-secrets-operator/pull/659)
* Core: Use exponential backoff on secret source errors: [GH-732](https://github.com/hashicorp/vault-secrets-operator/pull/732)

Fix:
* Core: call VDS callbacks on VaultAuth and VaultConnection changes: [GH-739](https://github.com/hashicorp/vault-secrets-operator/pull/739)
* Core: skip LifetimeWatcher validation for non-renewable auth tokens: [GH-722](https://github.com/hashicorp/vault-secrets-operator/pull/722)
* Core: disable development logger mode by default: [GH-751](https://github.com/hashicorp/vault-secrets-operator/pull/751)
* VSS: that spec.hmacSecretData's value is honoured: [GH-753](https://github.com/hashicorp/vault-secrets-operator/pull/753)
* VDS: Selectively log calls to SyncRegistry.Delete(): [GH-718](https://github.com/hashicorp/vault-secrets-operator/pull/718)

Build:
* CI: Bump test vault versions: [GH-861](https://github.com/hashicorp/vault-secrets-operator/pull/861)
* Bump GH actions for node 16 obsolescence: [GH-738](https://github.com/hashicorp/vault-secrets-operator/pull/738)

Dependency Updates:
* Bump TF provider versions: [GH-737](https://github.com/hashicorp/vault-secrets-operator/pull/737)
* Bump github.com/go-logr/logr from 1.4.1 to 1.4.2: [GH-775](https://github.com/hashicorp/vault-secrets-operator/pull/775)
* Bump github.com/hashicorp/go-getter from 1.7.1 to 1.7.4: [GH-711](https://github.com/hashicorp/vault-secrets-operator/pull/711)
* Bump github.com/hashicorp/vault/api from 1.12.2 to 1.13.0: [GH-725](https://github.com/hashicorp/vault-secrets-operator/pull/725)
* Bump github.com/hashicorp/vault/sdk from 0.12.0 to 0.13.0: [GH-773](https://github.com/hashicorp/vault-secrets-operator/pull/773)
* Bump github.com/onsi/gomega from 1.33.0 to 1.33.1: [GH-727](https://github.com/hashicorp/vault-secrets-operator/pull/727)
* Bump github.com/prometheus/client_golang from 1.19.0 to 1.19.1: [GH-741](https://github.com/hashicorp/vault-secrets-operator/pull/741)
* Bump golang.org/x/crypto from 0.22.0 to 0.23.0: [GH-744](https://github.com/hashicorp/vault-secrets-operator/pull/744)
* Bump google.golang.org/api from 0.176.1 to 0.177.0: [GH-724](https://github.com/hashicorp/vault-secrets-operator/pull/724)
* Bump google.golang.org/api from 0.180.0 to 0.181.0: [GH-758](https://github.com/hashicorp/vault-secrets-operator/pull/758)
* Bump k8s.io/api from 0.30.0 to 0.30.1: [GH-761](https://github.com/hashicorp/vault-secrets-operator/pull/761)
* Bump k8s.io/client-go from 0.30.0 to 0.30.1: [GH-760](https://github.com/hashicorp/vault-secrets-operator/pull/760)
* Bump sigs.k8s.io/controller-runtime from 0.18.2 to 0.18.3: [GH-772](https://github.com/hashicorp/vault-secrets-operator/pull/772)
* Bump ubi9/ubi-micro from 9.3-15 to 9.4-6: [GH-719](https://github.com/hashicorp/vault-secrets-operator/pull/719)
* Bump ubi9/ubi-minimal from 9.4-949 to 9.4-949.1714662671: [GH-728](https://github.com/hashicorp/vault-secrets-operator/pull/728)


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
