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
)

func TestStreamSecretEvents_VaultStaticSecretMatch(t *testing.T) {
	t.Parallel()

	vss := &secretsv1beta1.VaultStaticSecret{
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

	eventJSON := []byte(fmt.Sprintf(
		`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
		"kv/data/app/config",
		vss.Spec.Namespace,
	))

	cfg := &InstantUpdateConfig{}
	matched, err := cfg.streamSecretEvents(context.Background(), vss, websocket.MessageText, eventJSON)
	require.NoError(t, err)
	require.True(t, matched)
}

func TestStreamSecretEvents_VaultDynamicSecretMatch(t *testing.T) {
	t.Parallel()

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

	eventJSON := []byte(fmt.Sprintf(
		`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
		"db/creds/app",
		vds.Spec.Namespace,
	))

	cfg := &InstantUpdateConfig{}
	matched, err := cfg.streamSecretEvents(context.Background(), vds, websocket.MessageText, eventJSON)
	require.NoError(t, err)
	require.True(t, matched)
}

func TestStreamSecretEvents_NotModified(t *testing.T) {
	t.Parallel()

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

	eventJSON := []byte(fmt.Sprintf(
		`{"data":{"event":{"metadata":{"path":"%s","modified":"false"}},"namespace":"/%s"}}`,
		"db/creds/app",
		vds.Spec.Namespace,
	))

	cfg := &InstantUpdateConfig{}
	matched, err := cfg.streamSecretEvents(context.Background(), vds, websocket.MessageText, eventJSON)
	require.NoError(t, err)
	require.False(t, matched)
}
