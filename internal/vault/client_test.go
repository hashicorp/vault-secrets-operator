// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func Test_defaultClient_CheckExpiry(t *testing.T) {
	type fields struct {
		initialized bool
		lastResp    *api.Secret
		lastRenewal int64
	}
	type args struct {
		offset int64
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "valid-with-offset",
			fields: fields{
				initialized: true,
				lastResp: &api.Secret{
					Renewable: true,
					Auth: &api.SecretAuth{
						LeaseDuration: 30,
						Renewable:     true,
					},
				},
				lastRenewal: time.Now().Unix() - 25,
			},
			args: args{
				offset: 4,
			},
			want:    false,
			wantErr: assert.NoError,
		},
		{
			name: "valid-with-1s-lease-zero-offset",
			fields: fields{
				initialized: true,
				lastResp: &api.Secret{
					Renewable: true,
					Auth: &api.SecretAuth{
						LeaseDuration: 1,
						Renewable:     true,
					},
				},
				lastRenewal: time.Now().Unix(),
			},
			args: args{
				offset: 0,
			},
			want:    false,
			wantErr: assert.NoError,
		},
		{
			name: "expired-with-offset",
			fields: fields{
				initialized: true,
				lastResp: &api.Secret{
					Renewable: true,
					Auth: &api.SecretAuth{
						LeaseDuration: 30,
						Renewable:     true,
					},
				},
				lastRenewal: time.Now().Unix() - 25,
			},
			args: args{
				offset: 5,
			},
			want:    true,
			wantErr: assert.NoError,
		},
		{
			name: "expired-without-offset",
			fields: fields{
				initialized: true,
				lastResp: &api.Secret{
					Renewable: true,
					Auth: &api.SecretAuth{
						LeaseDuration: 30,
						Renewable:     true,
					},
				},
				lastRenewal: time.Now().Unix() - 30,
			},
			args: args{
				offset: 0,
			},
			want:    true,
			wantErr: assert.NoError,
		},
		{
			name: "error-not-initialized",
			fields: fields{
				initialized: false,
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.EqualError(t, err, "not initialized", i...)
				return err != nil
			},
		},
		{
			name: "error-lastResp-nil",
			fields: fields{
				initialized: true,
				lastRenewal: time.Now().Unix(),
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.EqualError(t, err, "cannot check client token expiry, never logged in", i...)
				return err != nil
			},
		},
		{
			name: "error-lastRenewal-zero",
			fields: fields{
				initialized: true,
				lastRenewal: 0,
				lastResp:    &api.Secret{},
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.EqualError(t, err, "cannot check client token expiry, never logged in", i...)
				return err != nil
			},
		},
		{
			name: "error-lastRenewal-zero-and-lasResp-nil",
			fields: fields{
				initialized: true,
				lastRenewal: 0,
				lastResp:    nil,
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.EqualError(t, err, "cannot check client token expiry, never logged in", i...)
				return err != nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultClient{
				initialized: tt.fields.initialized,
				lastResp:    tt.fields.lastResp,
				lastRenewal: tt.fields.lastRenewal,
			}
			got, err := c.CheckExpiry(tt.args.offset)
			if !tt.wantErr(t, err, fmt.Sprintf("CheckExpiry(%v)", tt.args.offset)) {
				return
			}
			assert.Equalf(t, tt.want, got, "CheckExpiry(%v)", tt.args.offset)
		})
	}
}
