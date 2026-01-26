// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"testing"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"nhooyr.io/websocket"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestStreamSecretEvents(t *testing.T) {
	t.Parallel()

	vssKVV2 := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: "default",
		},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			Namespace: "team-a",
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: "kv",
				Path:  "app/config",
				Type:  consts.KVSecretTypeV2,
			},
		},
	}

	vssKVV1 := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: "default",
		},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			Namespace: "team-a",
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: "kv",
				Path:  "app/config",
				Type:  consts.KVSecretTypeV1,
			},
		},
	}

	vds := &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: "default",
		},
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Namespace: "team-a",
			Mount:     "db",
			Path:      "creds/app",
		},
	}

	cfg := &InstantUpdateConfig{}
	tests := []struct {
		name      string
		obj       client.Object
		eventJSON []byte
		wantMatch bool
	}{
		{
			name: "vss-kvv2-match",
			obj:  vssKVV2,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"kv/data/app/config",
				vssKVV2.Spec.Namespace,
			)),
			wantMatch: true,
		},
		{
			name: "vss-kvv2-metadata-mismatch",
			obj:  vssKVV2,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"kv/metadata/app/config",
				vssKVV2.Spec.Namespace,
			)),
			wantMatch: false,
		},
		{
			name: "vss-kvv1-match",
			obj:  vssKVV1,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"kv/app/config",
				vssKVV1.Spec.Namespace,
			)),
			wantMatch: true,
		},
		{
			name: "vss-kvv1-mismatch",
			obj:  vssKVV1,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"kv/data/app/config",
				vssKVV1.Spec.Namespace,
			)),
			wantMatch: false,
		},
		{
			name: "vss-namespace-mismatch",
			obj:  vssKVV2,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"kv/data/app/config",
				"other-team",
			)),
			wantMatch: false,
		},
		{
			name: "not-modified",
			obj:  vds,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"false"}},"namespace":"/%s"}}`,
				"db/creds/app",
				vds.Spec.Namespace,
			)),
			wantMatch: false,
		},
		{
			name: "modified-missing",
			obj:  vssKVV2,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s"}},"namespace":"/%s"}}`,
				"kv/data/app/config",
				vssKVV2.Spec.Namespace,
			)),
			wantMatch: false,
		},
		{
			name: "missing-metadata-path",
			obj:  vssKVV2,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"modified":"true"}},"namespace":"/%s"}}`,
				vssKVV2.Spec.Namespace,
			)),
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matched, err := cfg.streamSecretEvents(context.Background(), tt.obj, websocket.MessageText, tt.eventJSON)
			require.NoError(t, err)
			require.Equal(t, tt.wantMatch, matched)
		})
	}
}
