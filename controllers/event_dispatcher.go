// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/types"
	"nhooyr.io/websocket"
)

type dispatcherMessage struct {
	msgType websocket.MessageType
	data    []byte
	err     error
}

type eventDispatcher struct {
	mu        sync.Mutex
	clientID  string
	conn      *websocket.Conn
	listeners map[types.NamespacedName]chan dispatcherMessage
	cancel    context.CancelFunc
	stopped   bool
}

var (
	dispatcherMu     sync.Mutex
	globalDispatcher *eventDispatcher
)

// getOrCreateDispatcher returns the shared dispatcher for the current Vault client.
func (cfg *InstantUpdateConfig) getOrCreateDispatcher(ctx context.Context) (*eventDispatcher, error) {
	dispatcherMu.Lock()
	defer dispatcherMu.Unlock()

	// Reuse the dispatcher when it is still valid for this Vault client.
	if globalDispatcher != nil && globalDispatcher.clientID == cfg.Client.ID() && !globalDispatcher.stopped {
		return globalDispatcher, nil
	}

	// Replace a stale dispatcher (different client or stopped) with a fresh one.
	if globalDispatcher != nil {
		globalDispatcher.stop()
		globalDispatcher = nil
	}

	wsClient, err := cfg.Client.WebsocketClient(instantUpdateEventPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create websocket client: %w", err)
	}

	conn, err := wsClient.Connect(ctx)
	if err != nil {
		return nil, err
	}

	readCtx, cancel := context.WithCancel(context.Background())
	d := &eventDispatcher{
		clientID:  cfg.Client.ID(),
		conn:      conn,
		cancel:    cancel,
		listeners: make(map[types.NamespacedName]chan dispatcherMessage),
	}
	globalDispatcher = d

	go d.readLoop(readCtx)

	return d, nil
}

// Register adds a listener for the object and returns its message channel.
func (d *eventDispatcher) Register(name types.NamespacedName) chan dispatcherMessage {
	d.mu.Lock()
	defer d.mu.Unlock()

	ch := make(chan dispatcherMessage, 10)
	d.listeners[name] = ch
	return ch
}

// Unregister removes a listener and closes its channel.
func (d *eventDispatcher) Unregister(name types.NamespacedName) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if ch, ok := d.listeners[name]; ok {
		close(ch)
		delete(d.listeners, name)
	}
}

// readLoop reads from the shared websocket and fan-outs messages to listeners.
func (d *eventDispatcher) readLoop(ctx context.Context) {
	for {
		msgType, data, err := d.conn.Read(ctx)

		d.mu.Lock()
		for _, ch := range d.listeners {
			select {
			case ch <- dispatcherMessage{msgType: msgType, data: data, err: err}:
			default:
			}
		}

		if err != nil || d.stopped {
			for name, ch := range d.listeners {
				close(ch)
				delete(d.listeners, name)
			}
			d.stopped = true
			d.mu.Unlock()
			dispatcherMu.Lock()
			if globalDispatcher == d {
				globalDispatcher = nil
			}
			dispatcherMu.Unlock()
			return
		}
		d.mu.Unlock()
	}
}

// stop shuts down the dispatcher and closes all listener channels.
func (d *eventDispatcher) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.stopped {
		return
	}
	d.stopped = true
	if d.cancel != nil {
		d.cancel()
	}
	if d.conn != nil {
		d.conn.Close(websocket.StatusNormalClosure, "closing websocket dispatcher")
	}
	for name, ch := range d.listeners {
		close(ch)
		delete(d.listeners, name)
	}
}
