// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/hashicorp/vault/api"
)

// TestHTTPServer creates a test HTTP server that handles requests until
// the listener returned is closed.
// XXX: based off of github.com/hashicorp/vault/api/client_test.go
func NewTestHTTPServer(t *testing.T, handler http.Handler) (*api.Config, net.Listener) {
	t.Helper()

	server, ln, err := testHTTPServer(handler, nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	go server.Serve(ln)

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("http://%s", ln.Addr())

	return config, ln
}

func testHTTPServer(handler http.Handler, tlsConfig *tls.Config) (*http.Server, net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}

	server := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	return server, ln, err
}

type testHandler struct {
	requestCount  int
	paths         []string
	params        []map[string]interface{}
	values        []url.Values
	excludeParams []string
	handlerFunc   func(t *testHandler, w http.ResponseWriter, req *http.Request)
}

func (t *testHandler) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		t.requestCount++

		t.paths = append(t.paths, req.URL.Path)

		var params map[string]interface{}
		switch req.Method {
		case http.MethodPut:
			b, err := io.ReadAll(req.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if len(b) > 0 {
				if err := json.Unmarshal(b, &params); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
		case http.MethodGet:
			if req.URL.RawQuery != "" {
				vals, err := url.ParseQuery(req.URL.RawQuery)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				t.values = append(t.values, vals)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		for _, p := range t.excludeParams {
			delete(params, p)
		}

		if len(params) > 0 {
			t.params = append(t.params, params)
		}

		t.handlerFunc(t, w, req)
	}
}
