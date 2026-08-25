// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"testing"

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

// TestVaultStaticSecretReconciler_Reconcile is a regression test for the
// HA-failover bug where VSO permanently stopped reconciling a VaultStaticSecret
// after a transient Vault error ("local node not active but active cluster node
// not found").
//
// Root cause: both error paths previously returned
// `ctrl.Result{RequeueAfter: horizon}, nil`. Once the RequeueAfter timer fired
// without Vault recovering, the resource fell out of the work queue permanently.
//
// Fix: return the non-nil error so controller-runtime's rate-limiter keeps the
// resource enqueued and retries indefinitely until Vault recovers.
func TestVaultStaticSecretReconciler_Reconcile(t *testing.T) {
	t.Parallel()

	vaultErr := errors.New("local node not active but active cluster node not found")

	tests := []struct {
		name string
		// factory is the ClientFactory the reconciler will use.
		factory vault.ClientFactory
		// preConditions are seeded onto the VSS status before reconciliation.
		preConditions []metav1.Condition
		// hmacEnabled, when true, enables HMAC secret data on the VSS spec.
		hmacEnabled bool
		// wantErr is the expected reconcile error (nil = success).
		wantErr error
		// wantRequeueAfter, when true, asserts result.RequeueAfter > 0.
		wantRequeueAfter bool
		// wantConditionStatus is the expected SecretSynced condition status.
		wantConditionStatus metav1.ConditionStatus
		// wantConditionReason is the expected SecretSynced condition reason.
		wantConditionReason string
	}{
		{
			// ClientFactory.Get fails — Vault auth / login unreachable during HA failover.
			// The reconciler must return the error so controller-runtime keeps the
			// resource in the rate-limiter queue for indefinite retry.
			name:                "clientFactory.Get error requeues indefinitely",
			factory:             &reconcileTestClientFactory{err: vaultErr},
			wantErr:             vaultErr,
			wantRequeueAfter:    true,
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: "Synced",
		},
		{
			// Client.Read fails — Vault returned 500 from a non-leader node.
			// Same requirement: error must propagate so the rate-limiter retries.
			name: "client.Read error requeues indefinitely",
			factory: &reconcileTestClientFactory{
				client: &reconcileTestVaultClient{
					MockRecordingVaultClient: &vault.MockRecordingVaultClient{
						CheckPaths: true, // no path configured → Read returns error
					},
					cacheKey: "k8s-test",
				},
			},
			wantErr:             assert.AnError, // any non-nil error
			wantRequeueAfter:    true,
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: "Synced",
		},
		{
			// Vault is healthy; VSS had a stale SecretSynced=False from a prior HA
			// failure. The reconciler must flip the condition back to True/Synced —
			// no manual spec-touch required.
			name: "successful read clears stale False condition",
			factory: &reconcileTestClientFactory{
				client: &reconcileTestVaultClient{
					MockRecordingVaultClient: &vault.MockRecordingVaultClient{},
					cacheKey:                 "k8s-test",
				},
			},
			preConditions: []metav1.Condition{
				{
					Type:               consts.TypeSecretSynced,
					Status:             metav1.ConditionFalse,
					Reason:             "Synced",
					Message:            "Failed to sync the secret, err=local node not active",
					LastTransitionTime: metav1.Now(),
				},
			},
			wantErr:             nil,
			wantRequeueAfter:    false, // no RefreshAfter set → RequeueAfter=0 on success
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: "Synced",
		},
		{
			// HMAC detects no data change (doSync=false). The SecretSynced condition
			// must still be written as True/Synced to clear any stale False entry.
			// Two reconciles are needed: the first stores the HMAC MAC, the second
			// sees a matching MAC and exercises the doSync=false branch.
			name:        "HMAC no-op reconcile writes True/Synced condition",
			hmacEnabled: true,
			factory: &reconcileTestClientFactory{
				client: &reconcileTestVaultClient{
					MockRecordingVaultClient: &vault.MockRecordingVaultClient{},
					cacheKey:                 "k8s-test",
				},
			},
			wantErr:             nil,
			wantRequeueAfter:    true,
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: "Synced",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			// Build a minimal VaultStaticSecret: kv-v1, destination.create=true so
			// the dest-exists check is bypassed.
			obj := &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", Generation: 1},
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
			if tt.hmacEnabled {
				v := true
				obj.Spec.HMACSecretData = &v
			}
			if len(tt.preConditions) > 0 {
				obj.Status.Conditions = tt.preConditions
			}

			fakeClient := testutils.NewFakeClientBuilder().
				WithStatusSubresource(obj).
				WithObjects(obj).
				Build()
			require.NoError(t, fakeClient.Status().Update(ctx, obj))

			hmacKey := client.ObjectKey{Name: "hmac-key", Namespace: "default"}
			if tt.hmacEnabled {
				_, err := helpers.CreateHMACKeySecret(ctx, fakeClient, hmacKey)
				require.NoError(t, err, "failed to create HMAC key secret")
			}

			r := &VaultStaticSecretReconciler{
				Client:                      fakeClient,
				SecretsClient:               fakeClient,
				ClientFactory:               tt.factory,
				SecretDataBuilder:           helpers.NewSecretsDataBuilder(),
				HMACValidator:               helpers.NewHMACValidator(hmacKey),
				Recorder:                    record.NewFakeRecorder(10),
				BackOffRegistry:             NewBackOffRegistry(),
				referenceCache:              NewResourceReferenceCache(),
				GlobalTransformationOptions: &helpers.GlobalTransformationOptions{},
				eventWatcherRegistry:        newEventWatcherRegistry(),
			}
			objKey := client.ObjectKeyFromObject(obj)

			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: objKey})

			if tt.hmacEnabled && err == nil {
				// First reconcile stores the MAC. Run a second reconcile with the
				// same generation so MACs match and doSync=false is exercised.
				updated := &secretsv1beta1.VaultStaticSecret{}
				require.NoError(t, fakeClient.Get(ctx, objKey, updated))
				updated.Generation = 1
				require.NoError(t, fakeClient.Update(ctx, updated))

				result, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: objKey})
			}

			if tt.wantErr != nil {
				if tt.wantErr == assert.AnError {
					require.Error(t, err, "expected a non-nil error to keep resource in the rate-limiter queue")
				} else {
					require.ErrorIs(t, err, tt.wantErr)
				}
			} else {
				require.NoError(t, err)
			}

			if tt.wantRequeueAfter {
				assert.Greater(t, result.RequeueAfter.Nanoseconds(), int64(0),
					"RequeueAfter must be set so the resource is retried")
			}

			// Verify SecretSynced condition.
			final := &secretsv1beta1.VaultStaticSecret{}
			require.NoError(t, fakeClient.Get(ctx, objKey, final))
			cond := findVSSCondition(final.Status.Conditions, consts.TypeSecretSynced)
			require.NotNil(t, cond, "SecretSynced condition must be present")
			assert.Equal(t, tt.wantConditionStatus, cond.Status)
			assert.Equal(t, tt.wantConditionReason, cond.Reason)
		})
	}
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
