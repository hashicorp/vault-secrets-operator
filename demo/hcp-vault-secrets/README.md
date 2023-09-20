### Demo Vault Secrets Operator and HCP Vault Secrets
This demo does the following:
- deploy the VSO to a kind K8S cluster
- configure VSO to sync a single HCP Vault Secrets App to K8s

Prerequisites:

- A HCP account
- A HCP project service principle created (contributor privileges)
- `git`
- `kind`
- `kubectl`
- `terraform`

### Run it

Create your HCP Vault Secrets app.
```
vlt apps create vso-demo
```

Create your kind K8s cluster
```shell
kind create cluster --name vault-secrets-operator
```


```shell
cd "$(git rev-parse --show-toplevel || echo .)/demo/hcp-vault-secrets"
terraform init
```

You will need to have the following handy:

- Your HCP organization ID
- Your HCP project ID
- A Service Principle's client ID
- A Service Principle's client secret/key

```shell
terraform apply
```

After running the command above, you should have a file called `scratch/demo.sh` in your current working directory

```shell
./scratch/demo.sh
```
Dump the K8s secret per the demo scripts instructions.

### Example run

#### terraform apply
```shell
$ terraform apply

╷
│ Warning: Provider development overrides are in effect
│ 
│ The following provider development overrides are set in the CLI configuration:
│  - hashicorp/vault in /Users/bash/.terraform.d/plugins
│ 
│ The behavior may therefore not match any released version of the provider and applying changes may cause the state to become incompatible with published releases.
╵
var.hcp_client_id
  Enter a value: 

var.hcp_client_secret
  Enter a value: 

var.hcp_organization_id
  Enter a value: xxxxxxxx-xxxxxxxx7-xxxx-xxxxxxxx4c33

var.hcp_project_id
  Enter a value: xxxxxxxx-xxxxxxxx8-xxxx-xxxxxxxx5d39

var.vault_secret_app_name
  Enter a value: vso-demo

module.vso-helm.helm_release.vault-secrets-operator: Refreshing state... [id=vault-secrets-operator]
kubernetes_namespace.demo: Refreshing state... [id=vault-secrets-demo-k8s-ns]
kubernetes_secret.sp: Refreshing state... [id=vault-secrets-demo-k8s-ns/vault-secrets-demo-sp]
local_file.demo-script: Refreshing state... [id=bf8f61187bb4f62a69bc2b605a8f1169ca0ddfe6]
local_file.hcp-auth: Refreshing state... [id=4cdd993fc9a7ffa259ffa04d7cd38e5406969a9e]

Note: Objects have changed outside of Terraform

Terraform detected the following changes made outside of Terraform since the last "terraform apply" which may have affected this plan:

  # kubernetes_namespace.demo has been deleted
  - resource "kubernetes_namespace" "demo" {
        id = "vault-secrets-demo-k8s-ns"

      - metadata {
          - name             = "vault-secrets-demo-k8s-ns" -> null
            # (5 unchanged attributes hidden)
        }
    }

  # module.vso-helm.helm_release.vault-secrets-operator has been deleted
  - resource "helm_release" "vault-secrets-operator" {
        id                         = "vault-secrets-operator"
        name                       = "vault-secrets-operator"
      - namespace                  = "vault-secrets-operator-system" -> null
        # (26 unchanged attributes hidden)

        # (8 unchanged blocks hidden)
    }


Unless you have made equivalent changes to your configuration, or ignored the relevant attributes using ignore_changes, the following plan may include actions to undo or respond to these changes.

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # kubernetes_namespace.demo will be created
  + resource "kubernetes_namespace" "demo" {
      + id = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "vault-secrets-demo-k8s-ns"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # kubernetes_secret.sp will be created
  + resource "kubernetes_secret" "sp" {
      + data                           = (sensitive value)
      + id                             = (known after apply)
      + type                           = "Opaque"
      + wait_for_service_account_token = true

      + metadata {
          + generation       = (known after apply)
          + name             = "vault-secrets-demo-sp"
          + namespace        = "vault-secrets-demo-k8s-ns"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

[...]

Plan: 3 to add, 0 to change, 0 to destroy.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

kubernetes_namespace.demo: Creating...
kubernetes_namespace.demo: Creation complete after 0s [id=vault-secrets-demo-k8s-ns]
kubernetes_secret.sp: Creating...
kubernetes_secret.sp: Creation complete after 0s [id=vault-secrets-demo-k8s-ns/vault-secrets-demo-sp]
module.vso-helm.helm_release.vault-secrets-operator: Creating...
module.vso-helm.helm_release.vault-secrets-operator: Still creating... [10s elapsed]
module.vso-helm.helm_release.vault-secrets-operator: Still creating... [20s elapsed]
module.vso-helm.helm_release.vault-secrets-operator: Creation complete after 23s [id=vault-secrets-operator]

Apply complete! Resources: 3 added, 0 changed, 0 destroyed.

Outputs:

demo_script = "./scratch/demo.sh"
k8s_namespace = "vault-secrets-demo-k8s-ns"
name_prefix = "vault-secrets-demo"
sp_secret_name = "vault-secrets-demo-sp"
```
#### demo script
```shell
$ ./scratch/demo.sh
run the following command to dump the HVS Secret data from K8s
kubectl get secret --namespace vault-secrets-demo-k8s-ns vault-secrets-demo-dest-secret -o yaml

$ kubectl get secret --namespace vault-secrets-demo-k8s-ns vault-secrets-demo-dest-secret -o yaml
apiVersion: v1
data:
  _raw: eyJzZWNyZXRzIjpbXX0=
kind: Secret
metadata:
  creationTimestamp: "2023-09-20T00:39:50Z"
  labels:
    app.kubernetes.io/component: secret-sync
    app.kubernetes.io/managed-by: hashicorp-vso
    app.kubernetes.io/name: vault-secrets-operator
    hvs: "true"
    secrets.hashicorp.com/vso-ownerRefUID: 446ba876-bf93-463a-a330-c1b9d512a395
  name: vault-secrets-demo-dest-secret
  namespace: vault-secrets-demo-k8s-ns
  ownerReferences:
  - apiVersion: secrets.hashicorp.com/v1beta1
    kind: HCPVaultSecretsApp
    name: hcpvs-demo
    uid: 446ba876-bf93-463a-a330-c1b9d512a395
  resourceVersion: "1183"
  uid: f129cff3-815b-43dc-a22d-eef283cfb720
type: Opaque
```
