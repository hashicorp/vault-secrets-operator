// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestEnsureInstantUpdateWatcher_StartsAndStops(t *testing.T) {
	obj := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	registry := newEventWatcherRegistry()
	backOff := NewBackOffRegistry(backoff.WithInitialInterval(time.Millisecond))
	sourceCh := make(chan event.GenericEvent, 1)
	recorder := record.NewFakeRecorder(5)
	client := newFakeVaultClient("client-id", &vault.WebsocketClient{})

	streamCalled := make(chan struct{}, 1)
	cfg := &InstantUpdateConfig{
		Object:          obj,
		Client:          client,
		WatchPath:       "/events",
		Registry:        registry,
		BackOffRegistry: backOff,
		SourceCh:        sourceCh,
		Recorder:        recorder,
		StreamSecretEvents: func(ctx context.Context, obj ctrlclient.Object, ws websocketConnector) error {
			select {
			case streamCalled <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return ctx.Err()
		},
		NewClientFunc: func(ctx context.Context, obj ctrlclient.Object) (vault.Client, error) {
			return client, nil
		},
	}

	require.NoError(t, StartInstantUpdateWatcher(context.Background(), cfg))

	select {
	case <-streamCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stream to be called")
	}

	key := ctrlclient.ObjectKeyFromObject(obj)
	meta, ok := registry.Get(key)
	require.True(t, ok)
	require.NotNil(t, meta)
	assert.Equal(t, obj.GetGeneration(), meta.LastGeneration)
	assert.Equal(t, client.ID(), meta.LastClientID)

	t.Cleanup(func() {
		StopInstantUpdateWatcher(registry, obj)
		waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		require.NoError(t, waitForStoppedCh(waitCtx, meta.StoppedCh))
	})
}

func TestEnsureInstantUpdateWatcher_RequeuesAfterErrors(t *testing.T) {
	obj := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	registry := newEventWatcherRegistry()
	backOff := NewBackOffRegistry(
		backoff.WithInitialInterval(time.Millisecond),
		backoff.WithMaxInterval(time.Millisecond),
		backoff.WithMultiplier(1.0),
	)
	sourceCh := make(chan event.GenericEvent, 1)
	recorder := record.NewFakeRecorder(10)
	client := newFakeVaultClient("client-id", &vault.WebsocketClient{})

	var streamCount int32
	cfg := &InstantUpdateConfig{
		Object:          obj,
		Client:          client,
		WatchPath:       "/events",
		Registry:        registry,
		BackOffRegistry: backOff,
		SourceCh:        sourceCh,
		Recorder:        recorder,
		StreamSecretEvents: func(ctx context.Context, obj ctrlclient.Object, ws websocketConnector) error {
			atomic.AddInt32(&streamCount, 1)
			return fmt.Errorf("boom")
		},
		NewClientFunc: func(ctx context.Context, obj ctrlclient.Object) (vault.Client, error) {
			return client, nil
		},
	}

	require.NoError(t, StartInstantUpdateWatcher(context.Background(), cfg))

	select {
	case evt := <-sourceCh:
		assert.Equal(t, obj.Namespace, evt.Object.GetNamespace())
		assert.Equal(t, obj.Name, evt.Object.GetName())
	case <-time.After(5 * time.Second):
		t.Fatal("expected requeue event after repeated errors")
	}

	key := ctrlclient.ObjectKeyFromObject(obj)
	require.Eventually(t, func() bool {
		_, ok := registry.Get(key)
		return !ok
	}, time.Second, time.Millisecond*10)

	assert.GreaterOrEqual(t, atomic.LoadInt32(&streamCount), int32(instantUpdateErrorThreshold))
}

type fakeVaultClient struct {
	vault.Client
	id             string
	websocket      *vault.WebsocketClient
	websocketError error
	websocketPath  string
}

func newFakeVaultClient(id string, ws *vault.WebsocketClient) *fakeVaultClient {
	return &fakeVaultClient{
		id:        id,
		websocket: ws,
	}
}

func (f *fakeVaultClient) ID() string {
	return f.id
}

func (f *fakeVaultClient) WebsocketClient(path string) (*vault.WebsocketClient, error) {
	f.websocketPath = path
	if f.websocketError != nil {
		return nil, f.websocketError
	}
	return f.websocket, nil
}

var _ vault.Client = (*fakeVaultClient)(nil)
