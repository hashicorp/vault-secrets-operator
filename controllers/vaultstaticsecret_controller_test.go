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

func TestStreamSecretEvents_KVv1PathMatch(t *testing.T) {
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
				Type:  consts.KVSecretTypeV1,
			},
		},
	}

	eventJSON := []byte(fmt.Sprintf(
		`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
		"kv/app/config",
		vss.Spec.Namespace,
	))

	cfg := &InstantUpdateConfig{}
	matched, err := cfg.streamSecretEvents(context.Background(), vss, websocket.MessageText, eventJSON)
	require.NoError(t, err)
	require.True(t, matched)
}
