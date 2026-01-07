// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"nhooyr.io/websocket"
)

func TestEventDispatcherRegisterUnregister(t *testing.T) {
	d := &eventDispatcher{
		listeners: make(map[types.NamespacedName]chan dispatcherMessage),
	}

	name := types.NamespacedName{Namespace: "default", Name: "test"}
	ch := d.Register(name)
	d.Unregister(name)

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected listener channel to be closed")
		}
	default:
		t.Fatalf("expected listener channel to be closed")
	}
}

func TestEventDispatcherReadLoopFanout(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"payload":"ok"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
		_ = conn.Write(context.Background(), websocket.MessageText, payload)
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close(websocket.StatusNormalClosure, "test done")
	})

	d := &eventDispatcher{
		conn:      conn,
		listeners: make(map[types.NamespacedName]chan dispatcherMessage),
	}

	ch1 := d.Register(types.NamespacedName{Namespace: "default", Name: "a"})
	ch2 := d.Register(types.NamespacedName{Namespace: "default", Name: "b"})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go d.readLoop(ctx)

	msg1 := waitForDispatcherMessage(t, ch1)
	msg2 := waitForDispatcherMessage(t, ch2)

	if msg1.msgType != websocket.MessageText || msg2.msgType != websocket.MessageText {
		t.Fatalf("expected text messages, got %v and %v", msg1.msgType, msg2.msgType)
	}
	if string(msg1.data) != string(payload) || string(msg2.data) != string(payload) {
		t.Fatalf("unexpected payloads: %q and %q", msg1.data, msg2.data)
	}
	if msg1.err != nil || msg2.err != nil {
		t.Fatalf("unexpected errors: %v and %v", msg1.err, msg2.err)
	}
}

func waitForDispatcherMessage(t *testing.T, ch <-chan dispatcherMessage) dispatcherMessage {
	t.Helper()

	select {
	case msg, ok := <-ch:
		if !ok {
			t.Fatalf("listener channel closed unexpectedly")
		}
		return msg
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for dispatcher message")
	}

	return dispatcherMessage{}
}
