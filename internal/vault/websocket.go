// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hashicorp/vault/api"
	"nhooyr.io/websocket"
)

type WebsocketClient struct {
	URL        string
	HTTPClient *http.Client
	Headers    http.Header
}

// WebSocketClient parses the vault client's address and scheme to create a websocket client
func (c *defaultClient) WebsocketClient() (*WebsocketClient, error) {
	vaultURL, err := url.Parse(c.client.Address())
	if err != nil {
		return nil, fmt.Errorf("failed to parse vault URL: %w", err)
	}
	vaultHost := vaultURL.Host

	// If we're using https, use wss, otherwise ws
	scheme := "wss"
	if vaultURL.Scheme == "http" {
		scheme = "ws"
	}

	// TODO(tvoran): move the kv path somewhere else to make this function more
	// generic
	webSocketURL := url.URL{
		Path:   "/v1/sys/events/subscribe/kv*",
		Host:   vaultHost,
		Scheme: scheme,
	}
	query := webSocketURL.Query()
	query.Set("json", "true")
	webSocketURL.RawQuery = query.Encode()

	headers := c.client.Headers()
	headers.Set(api.AuthHeaderName, c.client.Token())
	headers.Set(api.NamespaceHeaderName, c.client.Namespace())

	w := &WebsocketClient{
		URL:        webSocketURL.String(),
		HTTPClient: c.client.CloneConfig().HttpClient,
		Headers:    headers,
	}

	return w, nil
}

// Connect establishes a websocket connection to the vault server, following
// redirects if necessary to reach the leader.
func (w *WebsocketClient) Connect(ctx context.Context) (*websocket.Conn, error) {
	// We do ten attempts, to ensure we follow forwarding to the leader.
	var conn *websocket.Conn
	var resp *http.Response
	var err error

	for attempt := 0; attempt < 10; attempt++ {
		conn, resp, err = websocket.Dial(ctx, w.URL, &websocket.DialOptions{
			HTTPClient: w.HTTPClient,
			HTTPHeader: w.Headers,
		})
		if err == nil {
			break
		}

		if resp == nil {
			break
		} else if resp.StatusCode == http.StatusTemporaryRedirect {
			w.URL = resp.Header.Get("Location")
			continue
		} else {
			break
		}
	}

	if err != nil {
		errMessage := err.Error()
		if resp != nil {
			if resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("received 404 when opening web socket to %s, ensure Vault is Enterprise version 1.16 or above", w.URL)
			}
			if resp.StatusCode == http.StatusForbidden {
				var errBytes []byte
				errBytes, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					return nil, fmt.Errorf("error occurred when attempting to read error response from Vault server")
				}
				errMessage = string(errBytes)
			}
		}
		return nil, fmt.Errorf("error returned when opening event stream web socket to %s, "+
			"ensure VaultAuth role has correct permissions and Vault is Enterprise "+
			"version 1.16 or above: %s", w.URL, errMessage)
	}

	if conn == nil {
		return nil, fmt.Errorf("too many redirects as part of establishing web socket connection to %s", w.URL)
	}

	return conn, nil
}
