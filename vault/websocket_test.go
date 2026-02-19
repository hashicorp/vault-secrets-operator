// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

func TestWebSocketClient(t *testing.T) {
	tests := map[string]struct {
		client             *defaultClient
		eventSubscribePath string
		expectedURL        string
		expectedNamespace  string
		expectedToken      string
	}{
		"no-namespace-and-http": {
			client: func() *defaultClient {
				client, err := api.NewClient(nil)
				require.NoError(t, err)
				client.SetToken("foo")
				client.SetAddress("http://some-vault:1234")
				return &defaultClient{client: client}
			}(),
			eventSubscribePath: "subscribe/event/path",
			expectedURL:        "ws://some-vault:1234/subscribe/event/path?json=true",
			expectedNamespace:  "",
			expectedToken:      "foo",
		},
		"namespace-and-https-and-wildcard-path": {
			client: func() *defaultClient {
				client, err := api.NewClient(nil)
				require.NoError(t, err)
				client.SetToken("foo")
				client.SetNamespace("bar")
				return &defaultClient{client: client}
			}(),
			eventSubscribePath: "some-path*",
			expectedURL:        "wss://127.0.0.1:8200/some-path%2A?json=true",
			expectedNamespace:  "bar",
			expectedToken:      "foo",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ws, err := tc.client.WebsocketClient(tc.eventSubscribePath)
			require.NoError(t, err)
			require.NotNil(t, ws)
			assert.Equal(t, tc.expectedURL, ws.URL)
			assert.Equal(t, tc.expectedToken, ws.Headers.Get(api.AuthHeaderName))
			assert.Equal(t, tc.expectedNamespace, ws.Headers.Get(api.NamespaceHeaderName))
		})
	}
}

func TestConnect(t *testing.T) {
	tests := map[string]struct {
		handler *testHandler
		wantErr string
	}{
		"forbidden": {
			handler: &testHandler{
				handlerFunc: func(t *testHandler, w http.ResponseWriter, req *http.Request) {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte("permission denied"))
				},
			},
			wantErr: "error returned when opening event stream web socket to %s, " +
				"ensure VaultAuth role has correct permissions and Vault is Enterprise " +
				"version 1.16 or above: permission denied",
		},
		"not-found": {
			handler: &testHandler{
				handlerFunc: func(t *testHandler, w http.ResponseWriter, req *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte("not found"))
				},
			},
			wantErr: "received 404 when opening web socket to %s, ensure Vault is Enterprise version 1.16 or above",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			config, l := NewTestHTTPServer(t, tc.handler.handler())
			t.Cleanup(func() {
				l.Close()
			})
			// save the vault url for checking the error message
			vaultURL, err := url.Parse(config.Address)
			require.NoError(t, err)

			client, err := api.NewClient(config)
			require.NoError(t, err)
			c := &defaultClient{client: client}
			ws, err := c.WebsocketClient("/subscribe/event/path")
			require.NoError(t, err)

			conn, err := ws.Connect(context.Background())
			assert.Nil(t, conn)
			wantErr := fmt.Sprintf(tc.wantErr, "ws://"+vaultURL.Host+"/subscribe/event/path?json=true")
			assert.EqualError(t, err, wantErr)
		})
	}
}

func TestConnect_redirect(t *testing.T) {
	// Setup the handler and server for the redirected request
	redirectedHandler := &testHandler{
		handlerFunc: func(t *testHandler, w http.ResponseWriter, req *http.Request) {
			websocket.Accept(w, req, nil)
		},
	}
	redirectedConfig, redirectedL := NewTestHTTPServer(t, redirectedHandler.handler())
	t.Cleanup(func() {
		redirectedL.Close()
	})
	redirectedURL, err := url.Parse(redirectedConfig.Address)
	require.NoError(t, err)
	redirectedURLStr := fmt.Sprintf("ws://%s/subscribe/event/path?json=true", redirectedURL.Host)

	// Setup the handler and server for the initial request (that will be redirected)
	handler := &testHandler{
		handlerFunc: func(t *testHandler, w http.ResponseWriter, req *http.Request) {
			w.Header().Add("Location", redirectedURLStr)
			w.WriteHeader(http.StatusTemporaryRedirect)
			w.Write([]byte("redirecting"))
		},
	}
	config, l := NewTestHTTPServer(t, handler.handler())
	t.Cleanup(func() {
		l.Close()
	})

	// Save the initial Vault URL
	vaultURL, err := url.Parse(config.Address)
	require.NoError(t, err)

	client, err := api.NewClient(config)
	require.NoError(t, err)
	c := &defaultClient{client: client}
	ws, err := c.WebsocketClient("/subscribe/event/path")
	require.NoError(t, err)

	// The websocket client URL starts out the initial vault URL
	assert.Equal(t, fmt.Sprintf("ws://%s/subscribe/event/path?json=true", vaultURL.Host), ws.URL)

	conn, err := ws.Connect(context.Background())

	// The location redirect logic should have changed the websocket client URL,
	// and the connection should have been successful
	assert.Equal(t, redirectedURLStr, ws.URL)
	assert.NoError(t, err)
	require.NotNil(t, conn)
	t.Cleanup(func() {
		conn.Close(websocket.StatusNormalClosure, "test finished")
	})
}
