// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
)

// These specs exercise the generated VaultStaticSecret CRD against a real API
// server, which is the only place the schema changes for key aggregation are
// actually enforced. In particular they pin the fact that `spec.path` is
// optional, since dropping it from the CRD's `required` list is easy to undo
// by regenerating manifests from a reverted type.
//
// The "one of path or data" constraint is carried by an x-kubernetes-validations
// rule, which is only evaluated on Kubernetes 1.25+. envtest pins an older
// version here, so that case is covered by the controller-side
// validateVaultStaticSecretSpec unit tests instead.
var _ = Describe("VaultStaticSecret CRD schema", func() {
	ctx := context.Background()

	newVSS := func(name string, mutate func(*secretsv1beta1.VaultStaticSecret)) *secretsv1beta1.VaultStaticSecret {
		o := &secretsv1beta1.VaultStaticSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
			},
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				Destination: secretsv1beta1.Destination{
					Name:   name,
					Create: true,
				},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Mount: "kvv2",
					Type:  consts.KVSecretTypeV2,
				},
			},
		}
		mutate(o)
		return o
	}

	// created holds the resources to tear down after each spec. Ginkgo v1 has
	// no DeferCleanup, so cleanup is driven from AfterEach.
	var created []*secretsv1beta1.VaultStaticSecret

	AfterEach(func() {
		for _, o := range created {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, o))).To(Succeed())
		}
		created = nil
	})

	// create applies o and registers its deletion, returning the error so each
	// spec can assert on it.
	create := func(o *secretsv1beta1.VaultStaticSecret) error {
		err := k8sClient.Create(ctx, o)
		if err == nil {
			created = append(created, o)
		}
		return err
	}

	It("accepts the classic single-path form", func() {
		o := newVSS("vss-path-only", func(o *secretsv1beta1.VaultStaticSecret) {
			o.Spec.Path = "app/config"
		})
		Expect(create(o)).To(Succeed())
	})

	It("accepts an aggregated secret with no spec.path", func() {
		o := newVSS("vss-data-only", func(o *secretsv1beta1.VaultStaticSecret) {
			o.Spec.Data = map[string]string{
				"db-user":     "db1/schema1#db-user",
				"db-password": "db1/schema1#db-password#2",
				"token":       "app1#token",
			}
		})
		Expect(create(o)).To(Succeed())

		got := &secretsv1beta1.VaultStaticSecret{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(o), got)).To(Succeed())
		Expect(got.Spec.Path).To(BeEmpty())
		Expect(got.Spec.Data).To(Equal(o.Spec.Data))
	})

	It("accepts spec.path and spec.data together", func() {
		o := newVSS("vss-path-and-data", func(o *secretsv1beta1.VaultStaticSecret) {
			o.Spec.Path = "app/config"
			o.Spec.Data = map[string]string{"token": "app1#token"}
		})
		Expect(create(o)).To(Succeed())
	})

	It("drops an empty spec.data set through the typed client", func() {
		// `data` is `omitempty`, so an empty map never reaches the API server
		// and the resource is simply a classic single-path secret. This is
		// why the minProperties rule below has to be exercised through raw
		// YAML rather than the typed client.
		o := newVSS("vss-empty-data-typed", func(o *secretsv1beta1.VaultStaticSecret) {
			o.Spec.Path = "app/config"
			o.Spec.Data = map[string]string{}
		})
		Expect(create(o)).To(Succeed())

		got := &secretsv1beta1.VaultStaticSecret{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(o), got)).To(Succeed())
		Expect(got.Spec.Data).To(BeEmpty())
	})

	It("rejects an explicitly empty spec.data written as YAML", func() {
		// minProperties=1 keeps `data: {}` from quietly looking like an
		// aggregated secret that resolves to nothing.
		u := &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": secretsv1beta1.GroupVersion.String(),
				"kind":       "VaultStaticSecret",
				"metadata": map[string]any{
					"name":      "vss-empty-data-yaml",
					"namespace": "default",
				},
				"spec": map[string]any{
					"mount":       "kvv2",
					"type":        consts.KVSecretTypeV2,
					"path":        "app/config",
					"data":        map[string]any{},
					"destination": map[string]any{"name": "vss-empty-data-yaml", "create": true},
				},
			},
		}

		err := k8sClient.Create(ctx, u)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.data"))
	})
})
