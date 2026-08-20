// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

func Test_computePKIRenewalWindow(t *testing.T) {
	ctx := context.Background()
	// make tests more predictable by using a shared static timestamp and dropping
	// nanoseconds.
	staticNow := time.Unix(time.Now().Unix(), 0)
	defaultNowFunc := func() time.Time { return staticNow }

	type assertFunc func(assert.TestingT, time.Duration, ...interface{}) bool

	newInWindowAssertFunc := func(expected, boundary time.Duration) assertFunc {
		return func(t assert.TestingT, actual time.Duration, msg ...interface{}) bool {
			if assert.LessOrEqual(t, expected, actual, msg...) {
				return assert.LessOrEqual(t, actual, boundary)
			}
			return false
		}
	}
	newNotInWindowAssertFunc := func(expected, boundary time.Duration, withOffset bool) assertFunc {
		return func(t assert.TestingT, actual time.Duration, msg ...interface{}) bool {
			if withOffset {
				// if an offset is specified we expect the horizon+jitter to be between expected
				// and boundary.
				if assert.GreaterOrEqual(t, actual, expected, msg...) {
					return assert.LessOrEqual(t, actual, boundary)
				}
			} else {
				// if an offset is not specified we expect the horizon+jitter to be less than
				// expected and greater than the boundary.
				if assert.LessOrEqual(t, actual, expected, msg...) {
					return assert.GreaterOrEqual(t, actual, boundary)
				}
			}
			return false
		}
	}

	tests := []struct {
		name            string
		o               *secretsv1beta1.VaultPKISecret
		expirationDelta int64
		jitterPercent   float64
		wantInWindow    bool
		assertFunc      assertFunc
		minHorizon      time.Duration
	}{
		{
			name: "in-window-with-offset-overlap",
			o: &secretsv1beta1.VaultPKISecret{
				Spec: secretsv1beta1.VaultPKISecretSpec{
					ExpiryOffset: "30s",
				},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 30,
			assertFunc:      newInWindowAssertFunc(time.Second*1, time.Duration(1.05*float64(time.Second))),
			wantInWindow:    true,
		},
		{
			name: "in-window-without-offset-at-expiry",
			o: &secretsv1beta1.VaultPKISecret{
				Spec:   secretsv1beta1.VaultPKISecretSpec{},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 0,
			jitterPercent:   0.05,
			assertFunc:      newInWindowAssertFunc(time.Second*1, time.Duration(1.05*float64(time.Second))),
			wantInWindow:    true,
		},
		{
			name: "in-window-without-offset-beyond-expiry",
			o: &secretsv1beta1.VaultPKISecret{
				Spec:   secretsv1beta1.VaultPKISecretSpec{},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: -1,
			jitterPercent:   0.05,
			assertFunc:      newInWindowAssertFunc(time.Second*1, time.Duration(1.05*float64(time.Second))),
			wantInWindow:    true,
		},
		{
			name: "in-window-with-invalid-offset",
			o: &secretsv1beta1.VaultPKISecret{
				Spec: secretsv1beta1.VaultPKISecretSpec{
					ExpiryOffset: "30 s",
				},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: -1,
			jitterPercent:   0.05,
			assertFunc:      newInWindowAssertFunc(time.Second*1, time.Duration(1.05*float64(time.Second))),
			wantInWindow:    true,
		},
		{
			name: "not-in-window-computed-horizon-less-than-1s",
			o: &secretsv1beta1.VaultPKISecret{
				Spec:   secretsv1beta1.VaultPKISecretSpec{},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 1,
			jitterPercent:   0.05,
			assertFunc:      newInWindowAssertFunc(time.Second*1, time.Duration(1.2*float64(time.Second))),
			wantInWindow:    true,
			minHorizon:      time.Millisecond * 1100,
		},
		{
			name: "not-in-window-with-offset",
			o: &secretsv1beta1.VaultPKISecret{
				Spec: secretsv1beta1.VaultPKISecretSpec{
					ExpiryOffset: "10s",
				},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 60,
			jitterPercent:   0.05,
			assertFunc:      newNotInWindowAssertFunc(time.Second*50, time.Second*60, true),
			wantInWindow:    false,
		},
		{
			name: "not-in-window-without-offset",
			o: &secretsv1beta1.VaultPKISecret{
				Spec:   secretsv1beta1.VaultPKISecretSpec{},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 60,
			jitterPercent:   0.05,
			assertFunc:      newNotInWindowAssertFunc(time.Second*60, time.Second*57, false),
			wantInWindow:    false,
		},
		{
			name: "not-in-window-with-invalid-offset",
			o: &secretsv1beta1.VaultPKISecret{
				Spec: secretsv1beta1.VaultPKISecretSpec{
					ExpiryOffset: "10 s",
				},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 60,
			jitterPercent:   0.05,
			assertFunc:      newNotInWindowAssertFunc(time.Second*60, time.Second*57, false),
			wantInWindow:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nowFuncOrig := nowFunc
			minHorizonOrig := minHorizon
			if tt.minHorizon > 0 {
				minHorizon = tt.minHorizon
			}
			t.Cleanup(func() {
				nowFunc = nowFuncOrig
				minHorizon = minHorizonOrig
			})

			nowFunc = defaultNowFunc
			now := nowFunc()
			tt.o.Status.Expiration = now.Unix() + tt.expirationDelta
			gotHorizon, gotInWindow := computePKIRenewalWindow(ctx, tt.o, tt.jitterPercent)
			tt.assertFunc(t, gotHorizon, "computePKIRenewalWindow(%v, %v, %v)", ctx, tt.o, tt.jitterPercent)
			assert.Equalf(t, tt.wantInWindow, gotInWindow, "computePKIRenewalWindow(%v, %v, %v)", ctx, tt.o, tt.jitterPercent)
		})
	}
}

func Test_convertToK8sTLSSecretData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data map[string][]byte
		want map[string][]byte
	}{
		{
			name: "empty",
			data: map[string][]byte{},
			want: map[string][]byte{},
		},
		{
			name: "without-ca",
			data: map[string][]byte{
				"private_key": []byte("v_private_key"),
				"certificate": []byte("v_certificate"),
			},
			want: map[string][]byte{
				"private_key": []byte("v_private_key"),
				"certificate": []byte("v_certificate"),
				"tls.key":     []byte("v_private_key"),
				"tls.crt":     []byte("v_certificate"),
			},
		},
		{
			name: "with-ca-chain",
			data: map[string][]byte{
				"private_key": []byte("v_private_key"),
				"certificate": []byte("v_certificate"),
				"ca_chain":    []byte("v_ca_chain"),
			},
			want: map[string][]byte{
				"private_key": []byte("v_private_key"),
				"certificate": []byte("v_certificate"),
				"ca_chain":    []byte("v_ca_chain"),
				"tls.key":     []byte("v_private_key"),
				"tls.crt":     []byte("v_certificate\nv_ca_chain"),
			},
		},
		{
			name: "with-issuing-ca",
			data: map[string][]byte{
				"private_key": []byte("v_private_key"), "certificate": []byte("v_certificate"),
				"issuing_ca": []byte("v_issuing_ca"),
			},
			want: map[string][]byte{
				"private_key": []byte("v_private_key"),
				"certificate": []byte("v_certificate"),
				"issuing_ca":  []byte("v_issuing_ca"),
				"tls.key":     []byte("v_private_key"),
				"tls.crt":     []byte("v_certificate\nv_issuing_ca"),
				"ca.crt":      []byte("v_issuing_ca"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, convertToK8sTLSSecretData(tt.data), "convertToK8sTLSSecretData(%v)", tt.data)
		})
	}
}

func Test_getPath(t *testing.T) {
	t.Parallel()

	r := &VaultPKISecretReconciler{}

	tests := []struct {
		name string
		spec secretsv1beta1.VaultPKISecretSpec
		want string
	}{
		{
			name: "without-issuer-ref",
			spec: secretsv1beta1.VaultPKISecretSpec{
				Mount: "pki",
				Role:  "default",
			},
			want: "pki/issue/default",
		},
		{
			name: "with-issuer-ref",
			spec: secretsv1beta1.VaultPKISecretSpec{
				Mount:     "pki",
				IssuerRef: "MyCA",
				Role:      "default",
			},
			want: "pki/issuer/MyCA/issue/default",
		},
		{
			name: "with-issuer-ref-custom-mount",
			spec: secretsv1beta1.VaultPKISecretSpec{
				Mount:     "pki-int",
				IssuerRef: "MyCA",
				Role:      "my-role",
			},
			want: "pki-int/issuer/MyCA/issue/my-role",
		},
		{
			name: "without-issuer-ref-custom-mount",
			spec: secretsv1beta1.VaultPKISecretSpec{
				Mount: "pki-int",
				Role:  "my-role",
			},
			want: "pki-int/issue/my-role",
		},
		{
			// IssuerRef supports the literal string "default" to refer to the
			// mount's currently configured default issuer.
			name: "with-issuer-ref-literal-default",
			spec: secretsv1beta1.VaultPKISecretSpec{
				Mount:     "pki",
				IssuerRef: "default",
				Role:      "my-role",
			},
			want: "pki/issuer/default/issue/my-role",
		},
		{
			// IssuerRef also accepts a Vault-generated UUID directly.
			name: "with-issuer-ref-uuid",
			spec: secretsv1beta1.VaultPKISecretSpec{
				Mount:     "pki",
				IssuerRef: "2eb1671b-33d7-6f0b-6545-5c7702807d74",
				Role:      "default",
			},
			want: "pki/issuer/2eb1671b-33d7-6f0b-6545-5c7702807d74/issue/default",
		},
		{
			// An explicit empty IssuerRef must behave identically to omitting it.
			name: "with-empty-issuer-ref",
			spec: secretsv1beta1.VaultPKISecretSpec{
				Mount:     "pki",
				IssuerRef: "",
				Role:      "default",
			},
			want: "pki/issue/default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, r.getPath(tt.spec))
		})
	}
}
