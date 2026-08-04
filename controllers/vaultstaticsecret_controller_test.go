// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

// errClientFactory is a vault.ClientFactory whose Get always returns an error,
// simulating Vault being unreachable (e.g. HA failover, 500 from a non-leader).
type errClientFactory struct {
	err error
}

func (f *errClientFactory) Get(_ context.Context, _ client.Client, _ client.Object) (vault.Client, error) {
	return nil, f.err
}

func (f *errClientFactory) RegisterClientCallbackHandler(vault.ClientCallbackHandler) {}

// errReadVaultClient is a vault.Client whose Read always returns an error.
type errReadVaultClient struct {
	vault.Client
	cacheKey vault.ClientCacheKey
	err      error
}

func (c *errReadVaultClient) Read(_ context.Context, _ vault.ReadRequest) (vault.Response, error) {
	return nil, c.err
}
func (c *errReadVaultClient) ID() string                              { return "err-read-client" }
func (c *errReadVaultClient) GetCacheKey() (vault.ClientCacheKey, error) { return c.cacheKey, nil }
func (c *errReadVaultClient) Taint()                                  {}

// okReadVaultClient is a vault.Client whose Read always succeeds with empty data.
type okReadVaultClient struct {
	vault.Client
	cacheKey vault.ClientCacheKey
}

func (c *okReadVaultClient) Read(_ context.Context, _ vault.ReadRequest) (vault.Response, error) {
	return &vaultResponse{
		secret: &api.Secret{Data: map[string]interface{}{}},
		data:   map[string]interface{}{},
	}, nil
}
func (c *okReadVaultClient) ID() string                              { return "ok-read-client" }
func (c *okReadVaultClient) GetCacheKey() (vault.ClientCacheKey, error) { return c.cacheKey, nil }
func (c *okReadVaultClient) Taint()                                  {}

// newVSSReconciler builds a minimal VaultStaticSecretReconciler backed by a
// fake client pre-seeded with obj (including its Status).
func newVSSReconciler(t *testing.T, factory vault.ClientFactory, obj *secretsv1beta1.VaultStaticSecret) *VaultStaticSecretReconciler {
	t.Helper()
	c := testutils.NewFakeClientBuilder().
		WithStatusSubresource(obj).
		WithObjects(obj).
		Build()
	// WithObjects does not persist .Status for status-subresource types;
	// write it explicitly so the reconciler reads back the pre-seeded conditions.
	require.NoError(t, c.Status().Update(context.Background(), obj))
	return &VaultStaticSecretReconciler{
		Client:                      c,
		SecretsClient:               c,
		ClientFactory:               factory,
		SecretDataBuilder:           helpers.NewSecretsDataBuilder(),
		HMACValidator:               helpers.NewHMACValidator(client.ObjectKey{}),
		Recorder:                    record.NewFakeRecorder(10),
		BackOffRegistry:             NewBackOffRegistry(),
		referenceCache:              NewResourceReferenceCache(),
		GlobalTransformationOptions: &helpers.GlobalTransformationOptions{},
		eventWatcherRegistry:        newEventWatcherRegistry(),
	}
}

// newMinimalVSS returns a VaultStaticSecret with the minimum fields needed for
// reconciliation: kv-v1, destination.create=true so the dest-exists check is
// bypassed.
func newMinimalVSS(name, namespace string) *secretsv1beta1.VaultStaticSecret {
	return &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: "secret",
				Path:  "myapp/config",
				Type:  "kv-v1",
			},
			Destination: secretsv1beta1.Destination{
				Name:   "dest-secret",
				Create: true,
			},
		},
	}
}

// TestVaultStaticSecretReconciler_Reconcile_vaultClientError is a regression
// test for the HA-failover bug where VSO permanently stopped reconciling a
// VaultStaticSecret after a transient Vault error
// ("local node not active but active cluster node not found").
//
// Root cause: both error paths previously returned `ctrl.Result{RequeueAfter: horizon}, nil`.
// Once the RequeueAfter timer fired without Vault recovering the resource fell
// out of the work queue permanently.
//
// Fix: return the non-nil error so controller-runtime's rate-limiter keeps the
// resource enqueued and retries indefinitely until Vault recovers.
func TestVaultStaticSecretReconciler_Reconcile_vaultClientError(t *testing.T) {
	t.Parallel()

	vaultErr := errors.New("local node not active but active cluster node not found")

	tests := []struct {
		name    string
		factory vault.ClientFactory
	}{
		{
			// ClientFactory.Get fails — Vault auth login unreachable.
			name:    "clientFactory.Get error",
			factory: &errClientFactory{err: vaultErr},
		},
		{
			// Client.Read fails — Vault returned 500 from a non-leader node.
			name:    "client.Read error",
			factory: &reconcileTestClientFactory{client: &errReadVaultClient{cacheKey: "k8s-test", err: vaultErr}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			obj := newMinimalVSS("app", "default")
			r := newVSSReconciler(t, tt.factory, obj)
			objKey := client.ObjectKeyFromObject(obj)

			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: objKey})

			// Error must be non-nil so controller-runtime keeps the resource in
			// its rate-limiter queue indefinitely.
			require.Error(t, err, "expected non-nil error to keep resource in the rate-limiter queue")
			assert.ErrorIs(t, err, vaultErr)
			// RequeueAfter is still set to honour the backoff delay.
			assert.Greater(t, result.RequeueAfter.Nanoseconds(), int64(0))

			// SecretSynced condition must reflect the failure.
			updated := &secretsv1beta1.VaultStaticSecret{}
			require.NoError(t, r.Client.Get(ctx, objKey, updated))
			cond := findVSSCondition(updated.Status.Conditions, consts.TypeSecretSynced)
			require.NotNil(t, cond)
			assert.Equal(t, metav1.ConditionFalse, cond.Status)
		})
	}
}

// TestVaultStaticSecretReconciler_Reconcile_recoveryClears_SecretSynced verifies
// that once Vault becomes healthy again the SecretSynced condition flips back
// to True, clearing the stale False left by a prior HA failure — without
// requiring a manual spec-touch on the VaultStaticSecret.
func TestVaultStaticSecretReconciler_Reconcile_recoveryClears_SecretSynced(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	obj := newMinimalVSS("app", "default")
	hmacFalse := false
	obj.Spec.HMACSecretData = &hmacFalse

	// Simulate the stuck state left by a prior HA failure.
	obj.Status.Conditions = []metav1.Condition{
		{
			Type:               consts.TypeSecretSynced,
			Status:             metav1.ConditionFalse,
			Reason:             "Synced",
			Message:            "Failed to sync the secret, err=local node not active",
			LastTransitionTime: metav1.Now(),
		},
	}

	r := newVSSReconciler(t, &reconcileTestClientFactory{client: &okReadVaultClient{cacheKey: "k8s-test"}}, obj)
	objKey := client.ObjectKeyFromObject(obj)

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: objKey})
	require.NoError(t, err)

	updated := &secretsv1beta1.VaultStaticSecret{}
	require.NoError(t, r.Client.Get(ctx, objKey, updated))

	cond := findVSSCondition(updated.Status.Conditions, consts.TypeSecretSynced)
	require.NotNil(t, cond, "SecretSynced condition must be present after recovery")
	assert.Equal(t, metav1.ConditionTrue, cond.Status,
		"SecretSynced must be True after a successful Vault read — no spec-touch required")
}

// findVSSCondition returns the first condition with the given type, or nil.
func findVSSCondition(conditions []metav1.Condition, typ string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == typ {
			return &conditions[i]
		}
	}
	return nil
}
