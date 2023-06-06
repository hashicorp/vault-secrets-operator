// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentials

import (
	"fmt"
	"testing"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_generateVaultAuthUUID(t *testing.T) {
	realVaultAuth := &secretsv1alpha1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      "testname",
			Namespace: "testnamespace",
			UID:       "testuuid",
			Labels: map[string]string{
				"vault": "auth",
			},
		},
		Spec: secretsv1alpha1.VaultAuthSpec{
			VaultConnectionRef: "testconnection",
			Namespace:          "testnamespace",
			Method:             "aws",
			Mount:              "testaws",
			AWS: &secretsv1alpha1.VaultAuthConfigAWS{
				Role:   "testrole",
				Region: "us-test-1",
			},
		},
	}
	initialUUID, err := makeVaultAuthUUID(realVaultAuth)
	require.NoError(t, err)

	// change something outside the hashed fields - same generated UUID
	realVaultAuth.ObjectMeta.Labels["test"] = "label"

	checkUUID, err := makeVaultAuthUUID(realVaultAuth)
	require.NoError(t, err)
	assert.Equal(t, initialUUID, checkUUID)

	// change the UID - different generated UUID
	realVaultAuth.ObjectMeta.UID = "testuuidv2"
	checkUUIDv2, err := makeVaultAuthUUID(realVaultAuth)
	require.NoError(t, err)
	assert.NotEqual(t, checkUUID, checkUUIDv2)

	// change something in the spec - different generated UUID
	realVaultAuth.Spec.AWS.Region = "us-test-2"
	checkUUIDv3, err := makeVaultAuthUUID(realVaultAuth)
	require.NoError(t, err)
	assert.NotEqual(t, checkUUIDv2, checkUUIDv3)
}

func Test_getIRSAConfig(t *testing.T) {
	tests := map[string]struct {
		annotations    map[string]string
		expectedConfig *IRSAConfig
		expectedErr    string
	}{
		"all options": {
			annotations: map[string]string{
				AWSAnnotationAudience:        "www.this.www.that",
				AWSAnnotationRole:            "testrole",
				AWSAnnotationTokenExpiration: "600",
			},
			expectedConfig: &IRSAConfig{
				RoleARN:         "testrole",
				Audience:        "www.this.www.that",
				TokenExpiration: 600,
			},
		},
		"defaults and role": {
			annotations: map[string]string{
				AWSAnnotationRole: "testrole",
			},
			expectedConfig: &IRSAConfig{
				RoleARN:         "testrole",
				Audience:        AWSDefaultAudience,
				TokenExpiration: AWSDefaultTokenExpiration,
			},
		},
		"missing role-arn": {
			annotations: map[string]string{
				AWSAnnotationAudience: "test.aud",
			},
			expectedErr: fmt.Sprintf("missing %q annotation", AWSAnnotationRole),
		},
		"malformed expiration": {
			annotations: map[string]string{
				AWSAnnotationRole:            "testrole",
				AWSAnnotationTokenExpiration: "not-a-number",
			},
			expectedErr: fmt.Sprintf("failed to parse annotation %q: %q as int: %s",
				AWSAnnotationTokenExpiration, "not-a-number",
				`strconv.ParseInt: parsing "not-a-number": invalid syntax`),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			config, err := getIRSAConfig(tc.annotations)
			if tc.expectedErr != "" {
				assert.EqualError(t, err, tc.expectedErr)
			} else {
				assert.Equal(t, tc.expectedConfig, config)
			}
		})
	}
}
