// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credentials

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
