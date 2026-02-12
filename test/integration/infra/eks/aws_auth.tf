# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

module "iam_assumable_role" {
  source                         = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version                        = "5.20.0"
  create_role                    = true
  role_name                      = "iam-irsa-role-${random_string.suffix.result}"
  provider_url                   = replace(module.eks.cluster_oidc_issuer_url, "https://", "")
  role_policy_arns               = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
  oidc_subjects_with_wildcards   = ["system:serviceaccount:*:irsa-test"]
  oidc_fully_qualified_audiences = ["sts.amazonaws.com"]
}

# permissions needed for Vault's AWS auth client
data "aws_iam_policy_document" "vault_aws_auth" {
  statement {
    actions = [
      "iam:GetUser",
      "iam:GetRole",
      "iam:GetInstanceProfile",
      "ec2:DescribeInstances",
    ]
    resources = ["*"]
  }

  statement {
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::*:role/iam-irsa-role-*"]
  }
}

resource "aws_iam_policy" "vault_aws_auth" {
  name        = "vault-aws-auth-${random_string.suffix.result}"
  description = "Permissions needed for Vault's AWS auth client"
  policy      = data.aws_iam_policy_document.vault_aws_auth.json
}

# attach the vault_aws_auth permissions to the EKS cluster node IAM role, so
# that the Vault AWS client can auth as the node role and perform the Vault auth
# operations
resource "aws_iam_role_policy_attachment" "vault_aws_auth_attach" {
  role       = module.eks.eks_managed_node_groups["default_node_group"]["iam_role_name"]
  policy_arn = aws_iam_policy.vault_aws_auth.arn
}
