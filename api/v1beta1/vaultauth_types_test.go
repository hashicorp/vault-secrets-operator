// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVaultAuthConfigAppRole_Merge(t *testing.T) {
	type fields struct {
		RoleID    string
		SecretRef string
	}
	type args struct {
		other *VaultAuthConfigAppRole
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		// TODO: Add test cases.
		{
			name: "empty",
			fields: fields{
				RoleID:    "",
				SecretRef: "",
			},
			args: args{
				other: &VaultAuthConfigAppRole{
					RoleID:    "",
					SecretRef: "",
				},
			},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &VaultAuthConfigAppRole{
				RoleID:    tt.fields.RoleID,
				SecretRef: tt.fields.SecretRef,
			}
			tt.wantErr(t, a.Merge(tt.args.other), fmt.Sprintf("Merge(%v)", tt.args.other))
		})
	}
}
