// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/vault"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

func Test_clientCacheStorageCollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	ctx := context.Background()
	tests := []struct {
		name           string
		client         ctrlclient.Client
		errorClient    ctrlclient.Client
		expectedLength float64
		createEntries  int
	}{
		{
			name:           "length-zero",
			client:         fake.NewClientBuilder().Build(),
			expectedLength: 0,
		},
		{
			name:           "length-five",
			client:         fake.NewClientBuilder().Build(),
			expectedLength: 5,
			createEntries:  5,
		},
		{
			name:   "length-negative-one",
			client: fake.NewClientBuilder().Build(),
			// scheme-less client to be used where we want the clientCacheStorageCollector()
			// to encounter an clientCacheStorage error.
			errorClient:    fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build(),
			expectedLength: -1,
			createEntries:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// NewDefaultClientCacheStorage always requires a ctrlclient.Client that has the core scheme.
			storage, err := NewDefaultClientCacheStorage(ctx, tt.client, nil, nil)
			require.NoError(t, err)

			client := tt.client
			if tt.errorClient != nil {
				// in this case we want the Collector's client to produce an error when calling storage.Len(). The expectedLength should be -1,
				// denoting an error was encountered during the metrics collection.
				client = tt.errorClient
			}

			collector := newClientCacheStorageCollector(storage, ctx, client)
			reg.MustRegister(collector)

			t.Cleanup(func() {
				reg.Unregister(collector)
			})

			var secrets []*corev1.Secret
			for i := 0; i < int(tt.expectedLength); i++ {
				secrets = append(secrets, storeSecret(t, ctx, tt.client, storage, i))
			}

			mfs, err := reg.Gather()
			require.NoError(t, err)

			assert.Len(t, mfs, 1)
			for _, mf := range mfs {
				m := mf.GetMetric()
				switch name := mf.GetName(); name {
				case metricsFQNClientCacheStorageLength:
					assert.Equal(t, tt.expectedLength, *m[0].Gauge.Value)
				default:
					assert.Fail(t, "missing a test for metric %s", name)
				}
			}
		})
	}
}

func Test_clientCacheStorage_Metrics(t *testing.T) {
	ctx := context.Background()

	storeLabelPairs := []*io_prometheus_client.LabelPair{
		{
			Name:  pointer.String(metrics.LabelOperation),
			Value: pointer.String(metrics.OperationStore),
		},
	}
	restoreLabelPairs := []*io_prometheus_client.LabelPair{
		{
			Name:  pointer.String(metrics.LabelOperation),
			Value: pointer.String(metrics.OperationRestore),
		},
	}
	purgeLabelPairs := []*io_prometheus_client.LabelPair{
		{
			Name:  pointer.String(metrics.LabelOperation),
			Value: pointer.String(metrics.OperationPurge),
		},
	}
	pruneLabelPairs := []*io_prometheus_client.LabelPair{
		{
			Name:  pointer.String(metrics.LabelOperation),
			Value: pointer.String(metrics.OperationPrune),
		},
	}
	deleteLabelPairs := []*io_prometheus_client.LabelPair{
		{
			Name:  pointer.String(metrics.LabelOperation),
			Value: pointer.String(metrics.OperationDelete),
		},
	}
	configLabelPairs := []*io_prometheus_client.LabelPair{
		{
			Name:  pointer.String(metricsLabelEnforceEncryption),
			Value: pointer.String("false"),
		},
	}

	type expectedMetricVec struct {
		total       *float64
		errorsTotal *float64
		labelPairs  []*io_prometheus_client.LabelPair
	}
	type expected struct {
		reqs *expectedMetricVec
		ops  *expectedMetricVec
	}

	type expectMetrics struct {
		store   *expected
		purge   *expected
		prune   *expected
		delete  *expected
		restore *expected
	}

	tests := []struct {
		name                string
		client              ctrlclient.Client
		errorClient         ctrlclient.Client
		expectedMetricCount int
		expectedLength      float64
		expectMetrics       expectMetrics
	}{
		{
			name:                "store-zero",
			client:              fake.NewClientBuilder().Build(),
			expectedLength:      0,
			expectedMetricCount: 2,
		},
		{
			name:                "store",
			client:              fake.NewClientBuilder().Build(),
			expectedLength:      5,
			expectedMetricCount: 6,
			expectMetrics: expectMetrics{
				store: &expected{
					reqs: &expectedMetricVec{
						total:       pointer.Float64(5),
						labelPairs:  storeLabelPairs,
						errorsTotal: pointer.Float64(2),
					},
					ops: &expectedMetricVec{
						total:       pointer.Float64(5),
						errorsTotal: pointer.Float64(2),
						labelPairs:  storeLabelPairs,
					},
				},
			},
		},
		{
			name:                "restore",
			client:              fake.NewClientBuilder().Build(),
			errorClient:         fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build(),
			expectedLength:      4,
			expectedMetricCount: 5,
			expectMetrics: expectMetrics{
				store: &expected{
					reqs: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: storeLabelPairs,
					},
					ops: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: storeLabelPairs,
					},
				},
				restore: &expected{
					reqs: &expectedMetricVec{
						total:       pointer.Float64(2),
						errorsTotal: pointer.Float64(4),
						labelPairs:  restoreLabelPairs,
					},
					ops: &expectedMetricVec{
						total:       pointer.Float64(2),
						errorsTotal: pointer.Float64(4),
						labelPairs:  restoreLabelPairs,
					},
				},
			},
		},
		{
			name:                "prune",
			client:              fake.NewClientBuilder().Build(),
			expectedLength:      2,
			expectedMetricCount: 5,
			expectMetrics: expectMetrics{
				store: &expected{
					reqs: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: storeLabelPairs,
					},
					ops: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: storeLabelPairs,
					},
				},
				prune: &expected{
					reqs: &expectedMetricVec{
						total:       pointer.Float64(2),
						errorsTotal: pointer.Float64(1),
						labelPairs:  pruneLabelPairs,
					},
					ops: &expectedMetricVec{
						total:       pointer.Float64(2),
						errorsTotal: pointer.Float64(1),
						labelPairs:  pruneLabelPairs,
					},
				},
				delete: &expected{
					reqs: &expectedMetricVec{
						total:       pointer.Float64(2),
						errorsTotal: pointer.Float64(1),
						labelPairs:  deleteLabelPairs,
					},
					ops: &expectedMetricVec{
						total:       pointer.Float64(2),
						errorsTotal: pointer.Float64(1),
						labelPairs:  deleteLabelPairs,
					},
				},
			},
		},
		{
			name:                "purge",
			client:              fake.NewClientBuilder().Build(),
			errorClient:         fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build(),
			expectedLength:      0,
			expectedMetricCount: 5,
			expectMetrics: expectMetrics{
				store: &expected{
					reqs: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: storeLabelPairs,
					},
					ops: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: storeLabelPairs,
					},
				},
				purge: &expected{
					reqs: &expectedMetricVec{
						total:       pointer.Float64(1),
						errorsTotal: pointer.Float64(1),
						labelPairs:  purgeLabelPairs,
					},
					ops: &expectedMetricVec{
						total:       pointer.Float64(1),
						errorsTotal: pointer.Float64(1),
						labelPairs:  purgeLabelPairs,
					},
				},
				prune: &expected{
					reqs: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: pruneLabelPairs,
					},
					ops: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: pruneLabelPairs,
					},
				},
			},
		},
		{
			name:                "restore-all",
			client:              fake.NewClientBuilder().Build(),
			errorClient:         fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build(),
			expectedLength:      4,
			expectedMetricCount: 4,
			expectMetrics: expectMetrics{
				store: &expected{
					reqs: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: storeLabelPairs,
					},
					ops: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: storeLabelPairs,
					},
				},
				restore: &expected{
					reqs: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: restoreLabelPairs,
					},
					ops: &expectedMetricVec{
						total:      pointer.Float64(4),
						labelPairs: restoreLabelPairs,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			// NewDefaultClientCacheStorage always requires a ctrlclient.Client that has the core scheme.
			storage, err := NewDefaultClientCacheStorage(ctx, tt.client, nil, reg)
			require.NoError(t, err)

			var secrets []*corev1.Secret
			// induce some metrics by executing the operations from tt.
			induce := func(t *testing.T, mv *expectedMetricVec) {
				t.Helper()
				require.NotNil(t, mv)
				require.NotNil(t, mv.total)

				count := int(*mv.total)
				for i := 0; i < count; i++ {
					for _, p := range mv.labelPairs {
						switch opType := p.GetValue(); opType {
						case metrics.OperationStore:
							secrets = append(secrets, storeSecret(t, ctx, tt.client, storage, i))
						case metrics.OperationRestore:
							require.LessOrEqual(t, count, len(secrets))
							secret := secrets[i]
							_, err := storage.Restore(ctx, tt.client, ClientCacheStorageRestoreRequest{
								SecretObjKey: ctrlclient.ObjectKeyFromObject(secret),
								CacheKey:     ClientCacheKey(secret.Labels[labelCacheKey]),
							})
							require.NoError(t, err)
						case metrics.OperationPrune:
							// prune() is a sub operation of purge, so there is no need to induce it when a purge() test is expected.
							if tt.expectMetrics.purge != nil {
								continue
							}
							require.LessOrEqual(t, count, len(secrets))
							secret := secrets[i]
							_, err := storage.Prune(ctx, tt.client, ClientCacheStoragePruneRequest{
								MatchingLabels: secret.Labels,
							})
							require.NoError(t, err)
						case metrics.OperationPurge:
							err := storage.Purge(ctx, tt.client)
							require.NoError(t, err)
						default:
							assert.Fail(t, "unsupported metrics operation type %q", opType)
						}
					}
				}
			}

			// induce some error metrics by executing the operations from tt.
			induceErrors := func(t *testing.T, mv *expectedMetricVec) {
				t.Helper()
				if mv == nil {
					return
				}
				if mv.errorsTotal == nil {
					return
				}
				client := tt.client
				if tt.errorClient != nil {
					client = tt.errorClient
				}
				for i := 0; i < int(*mv.errorsTotal); i++ {
					for _, p := range mv.labelPairs {
						switch opType := p.GetValue(); opType {
						case metrics.OperationStore:
							_, err := storage.Store(ctx, client, ClientCacheStorageStoreRequest{})
							assert.Error(t, err)
						case metrics.OperationRestore:
							_, err := storage.Restore(ctx, client, ClientCacheStorageRestoreRequest{})
							assert.Error(t, err)
						case metrics.OperationPurge:
							err := storage.Purge(ctx, client)
							assert.Error(t, err)
						case metrics.OperationPrune:
							_, err := storage.Prune(ctx, client, ClientCacheStoragePruneRequest{})
							assert.Error(t, err)
						case metrics.OperationDelete:
						default:
							assert.Fail(t, "unsupported metrics operation type %q", opType)
						}
					}
				}
			}

			for _, e := range []*expected{tt.expectMetrics.store, tt.expectMetrics.restore, tt.expectMetrics.purge, tt.expectMetrics.prune} {
				if e == nil {
					continue
				}
				if e.reqs == nil {
					continue
				}
				if e.reqs.total != nil {
					induce(t, e.reqs)
				}
				if e.reqs.errorsTotal != nil {
					induceErrors(t, e.reqs)
				}
			}

			assertCounterMetricVec := func(t *testing.T, e *expectedMetricVec, name, operation string, m *io_prometheus_client.Metric, checkErrors bool) {
				msgFmt := "unexpected metric value for %s, operation=%s"
				if e != nil {
					if !checkErrors {
						if e.total != nil {
							assert.Equal(t, *e.total, *m.Counter.Value, msgFmt, name, operation)
							assert.Equal(t, e.labelPairs, m.Label, msgFmt, name, operation)
						}
					} else {
						if e.errorsTotal != nil {
							assert.Equal(t, *e.errorsTotal, *m.Counter.Value, msgFmt, name, operation)
							assert.Equal(t, e.labelPairs, m.Label, msgFmt, name, operation)
						}
					}
				}
			}

			assertMetrics := func(t *testing.T, metric []*io_prometheus_client.Metric, name string, checkErrors bool) {
				for _, m := range metric {
					var e *expected
					var opType string
					for _, p := range m.GetLabel() {
						switch opType = p.GetValue(); opType {
						case metrics.OperationStore:
							e = tt.expectMetrics.store
						case metrics.OperationRestore:
							e = tt.expectMetrics.restore
						case metrics.OperationPurge:
							e = tt.expectMetrics.purge
						case metrics.OperationPrune:
							e = tt.expectMetrics.prune
						case metrics.OperationDelete:
							e = tt.expectMetrics.delete
						default:
							require.Failf(t, "unsupported metrics operation", "type %s", opType)

						}
					}

					if e.reqs != nil {
						assertCounterMetricVec(t, e.reqs, name, opType, m, checkErrors)
					}
					if e.ops != nil {
						assertCounterMetricVec(t, e.ops, name, opType, m, checkErrors)
					}

					require.False(t, e.ops == nil && e.reqs == nil, "no tests set for metric %s and operation %s", name, opType)
				}
			}

			mfs, err := reg.Gather()
			require.NoError(t, err)
			require.Len(t, mfs, tt.expectedMetricCount)
			for _, mf := range mfs {
				m := mf.GetMetric()
				msgFmt := "unexpected metric %s for %s"
				switch name := mf.GetName(); name {
				case metricsFQNClientCacheStorageConfig:
					assert.Equal(t, float64(1), m[0].Gauge.GetValue(), msgFmt, "value", name)
					assert.Equal(t, configLabelPairs, m[0].Label, msgFmt, "label", name)
				case metricsFQNClientCacheStorageLength:
					assert.Equal(t, tt.expectedLength, m[0].Gauge.GetValue(), msgFmt, "value", name)
				case metricsFQNClientCacheStorageReqsTotal:
					assertMetrics(t, m, name, false)
				case metricsFQNClientCacheStorageReqsErrorsTotal:
					assertMetrics(t, m, name, true)
				case metricsFQNClientCacheStorageOpsTotal:
					assertMetrics(t, m, name, false)
				case metricsFQNClientCacheStorageOpsErrorsTotal:
					assertMetrics(t, m, name, true)
				default:
					assert.Fail(t, "missing a test for metric %s", name)
				}
			}
		})
	}
}

func storeSecret(t *testing.T, ctx context.Context, client ctrlclient.Client, storage ClientCacheStorage, i int) *corev1.Secret {
	t.Helper()
	req := ClientCacheStorageStoreRequest{
		Client: &defaultClient{
			authObj: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:       fmt.Sprintf("auth-%d", i),
					UID:        types.UID(uuid.New().String()),
					Generation: 0,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "kubernetes",
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name:       fmt.Sprintf("conn-%d", i),
					UID:        types.UID(uuid.New().String()),
					Generation: 0,
				},
			},
			credentialProvider: vault.NewKubernetesCredentialProvider(nil, "",
				types.UID(uuid.New().String())),
		},
	}
	secret, err := storage.Store(ctx, client, req)
	require.NoError(t, err)
	return secret
}
