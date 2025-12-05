// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
)

var (
	defaultHMACKey    []byte
	defaultHMACObjKey = client.ObjectKey{
		Namespace: "vso",
		Name:      "hmac",
	}
)

func init() {
	var err error
	defaultHMACKey, err = generateHMACKey()
	if err != nil {
		panic(err)
	}
}

func Test_generateHMACKey(t *testing.T) {
	tests := []struct {
		name           string
		count          int
		wantErr        assert.ErrorAssertionFunc
		randReadFunc   func([]byte) (n int, err error)
		expectedLength int
	}{
		{
			name:           "basic",
			count:          100,
			wantErr:        assert.NoError,
			expectedLength: hmacKeyLength,
		},
		{
			name:           "error-permission-denied",
			count:          1,
			expectedLength: 0,
			randReadFunc: func(bytes []byte) (n int, err error) {
				return 0, os.ErrPermission
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, os.ErrPermission)
			},
		},
		{
			// verifies that the previous error test put things back in order
			name:           "another",
			count:          100,
			wantErr:        assert.NoError,
			expectedLength: hmacKeyLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.randReadFunc != nil {
				t.Cleanup(func() {
					randRead = rand.Read
				})
				randRead = tt.randReadFunc
			}

			var last []byte
			for i := 0; i < tt.count; i++ {
				got, err := generateHMACKey()
				if !tt.wantErr(t, err, fmt.Sprintf("generateHMACKey()")) {
					return
				}

				assert.Len(t, got, tt.expectedLength, "generateHMACKey()")
				if last != nil {
					assert.NotEqual(t, got, last, "generateHMACKey() generated a duplicate key")
				}
				last = got
			}
		})
	}
}

func TestCreateHMACKeySecret(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		objKey  client.ObjectKey
		want    *corev1.Secret
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			objKey: client.ObjectKey{
				Namespace: "vso",
				Name:      "hmac",
			},
			want: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "vso",
					Name:      "hmac",
				},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testutils.NewFakeClient()
			got, err := CreateHMACKeySecret(ctx, c, tt.objKey)
			if !tt.wantErr(t, err, fmt.Sprintf("CreateHMACKeySecret(%v, %v, %v)", ctx, c, tt.objKey)) {
				return
			}

			if err != nil {
				assert.Nil(t, got, "CreateHMACKeySecret(%v, %v, %v)", ctx, c, tt.objKey)
				return
			}

			require.NotNil(t, got, "CreateHMACKeySecret(%v, %v, %v)", ctx, c, tt.objKey)
			assert.Equal(t, tt.want.GetName(), got.GetName(), "CreateHMACKeySecret(%v, %v, %v)", ctx, c, tt.objKey)
			assert.Equal(t, tt.want.GetNamespace(), got.GetNamespace(), "CreateHMACKeySecret(%v, %v, %v)", ctx, c, tt.objKey)
			assert.NoError(t, validateKeyLength(got.Data[HMACKeyName]))
			assert.Equal(t, got.Labels, hmacSecretLabels)
		})
	}
}

// handleSecretHMACTest is a subtest structure of hmacSecretTestCase
type handleSecretHMACTest struct {
	data    map[string][]byte
	wantMAC []byte
}

type hmacSecretTestCase struct {
	name               string
	objMeta            metav1.ObjectMeta
	validator          HMACValidator
	withTransOpt       bool
	transOpt           *SecretTransformationOption
	want               bool
	data               map[string][]byte
	hmacKey            []byte
	secretMAC          string
	invalidObjKind     bool
	noCreateHMACSecret bool
	destination        secretsv1beta1.Destination
	wantErr            assert.ErrorAssertionFunc
	handleSecretHMAC   handleSecretHMACTest
}

func getHMACObjsMap(t *testing.T, tt hmacSecretTestCase) map[string]client.Object {
	t.Helper()
	m := make(map[string]client.Object)

	if tt.invalidObjKind {
		m["invalid"] = &corev1.Secret{}
		return m
	}

	for _, objKind := range []string{"vds", "vps", "vss", "hcpvs"} {
		d := tt.destination.DeepCopy()
		if tt.destination.Name != "" {
			d.Name = d.Name + "_" + objKind
		}
		switch objKind {
		case "vds":
			m[objKind] = &secretsv1beta1.VaultDynamicSecret{
				ObjectMeta: tt.objMeta,
				Spec:       secretsv1beta1.VaultDynamicSecretSpec{Destination: *d},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretMAC: tt.secretMAC,
				},
			}
		case "vps":
			m[objKind] = &secretsv1beta1.VaultPKISecret{
				ObjectMeta: tt.objMeta,
				Spec: secretsv1beta1.VaultPKISecretSpec{
					Destination: *d,
				},
				Status: secretsv1beta1.VaultPKISecretStatus{
					SecretMAC: tt.secretMAC,
				},
			}
		case "vss":
			m[objKind] = &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: tt.objMeta,
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					Destination: *d,
				},
				Status: secretsv1beta1.VaultStaticSecretStatus{
					SecretMAC: tt.secretMAC,
				},
			}
		case "hcpvs":
			m[objKind] = &secretsv1beta1.HCPVaultSecretsApp{
				ObjectMeta: tt.objMeta,
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					Destination: *d,
				},
				Status: secretsv1beta1.HCPVaultSecretsAppStatus{
					SecretMAC: tt.secretMAC,
				},
			}
		}
	}

	return m
}

func TestHMACDestinationSecret(t *testing.T) {
	t.Parallel()

	defaultData := map[string][]byte{
		"foo": []byte(`baz`),
	}
	defaultHMAC, err := MACMessage(defaultHMACKey, marshalRaw(t, defaultData))
	require.NoError(t, err)
	defaultSecretMAC := base64.StdEncoding.EncodeToString(defaultHMAC)

	otherData := map[string][]byte{
		"foo": []byte(`baz`),
		"baz": []byte(`buz`),
	}
	otherHMAC, err := MACMessage(defaultHMACKey, marshalRaw(t, otherData))
	require.NoError(t, err)
	otherSecretMAC := base64.StdEncoding.EncodeToString(otherHMAC)

	objMeta := metav1.ObjectMeta{
		Namespace: "foo",
		Name:      "bar",
	}

	tests := []hmacSecretTestCase{
		{
			name:      "matched",
			secretMAC: defaultSecretMAC,
			objMeta:   objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			data:    defaultData,
			wantErr: assert.NoError,
			want:    true,
		},
		{
			name:      "matched-with-transopts",
			secretMAC: defaultSecretMAC,
			objMeta:   objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			withTransOpt: true,
			transOpt: &SecretTransformationOption{
				Excludes: []string{"^baz$"},
			},
			data:    defaultData,
			wantErr: assert.NoError,
			want:    true,
		},
		{
			name:    "mismatch-empty-secretMAC",
			objMeta: objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			data:    defaultData,
			want:    false,
			wantErr: assert.NoError,
		},
		{
			name:    "mismatch-secretMAC",
			objMeta: objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			secretMAC: otherSecretMAC,
			data:      defaultData,
			want:      false,
			wantErr:   assert.NoError,
		},
		{
			name:    "mismatch-destination-inexistent",
			objMeta: objMeta,
			data:    defaultData,
			want:    false,
			wantErr: assert.NoError,
		},
		{
			name:    "error-invalid-secretMAC",
			objMeta: objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			secretMAC: "bbb" + defaultSecretMAC,
			data:      defaultData,
			want:      false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "illegal base64 data at input byte 47", i...)
			},
		},
		{
			name:           "error-invalid-objKind",
			invalidObjKind: true,
			want:           false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "unsupported object type *v1.Secret", i...)
			},
		},
		{
			name:               "error-no-HMAC-k8s-Secret",
			noCreateHMACSecret: true,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			secretMAC: defaultSecretMAC,
			want:      false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				if assert.EqualError(t, err, fmt.Sprintf(
					`encountered an error getting %q: secrets "%s" not found`,
					defaultHMACObjKey, defaultHMACObjKey.Name), i...) {
					return assert.True(t, errors.IsNotFound(err))
				}
				return false
			},
		},
		{
			name: "error-invalid-HMAC-key",
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			secretMAC: defaultSecretMAC,
			want:      false,
			hmacKey:   []byte(`bb`),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, `invalid key length 2`, i...)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertSecretHMAC(t, tt, testutils.NewFakeClient())
		})
	}
}

func TestHandleDestinationSecret(t *testing.T) {
	t.Parallel()

	defaultData := map[string][]byte{
		"foo": []byte(`baz`),
	}

	newData := map[string][]byte{
		"buz": []byte(`qux`),
	}

	defaultHMAC, err := MACMessage(defaultHMACKey, marshalRaw(t, defaultData))
	require.NoError(t, err)
	defaultSecretMAC := base64.StdEncoding.EncodeToString(defaultHMAC)

	newDataHMAC, err := MACMessage(defaultHMACKey, marshalRaw(t, newData))
	require.NoError(t, err)

	objMeta := metav1.ObjectMeta{
		Namespace: "foo",
		Name:      "bar",
	}

	otherData := map[string][]byte{
		"foo": []byte(`baz`),
		"baz": []byte(`buz`),
	}

	tests := []hmacSecretTestCase{
		{
			name:      "matched",
			secretMAC: defaultSecretMAC,
			objMeta:   objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			data: defaultData,
			handleSecretHMAC: handleSecretHMACTest{
				data:    defaultData,
				wantMAC: defaultHMAC,
			},
			wantErr: assert.NoError,
			want:    true,
		},
		{
			name:      "matched-with-transopts",
			secretMAC: defaultSecretMAC,
			objMeta:   objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			data: otherData,
			handleSecretHMAC: handleSecretHMACTest{
				data:    defaultData,
				wantMAC: defaultHMAC,
			},
			withTransOpt: true,
			transOpt: &SecretTransformationOption{
				Excludes: []string{"^baz$"},
			},
			wantErr: assert.NoError,
			want:    true,
		},
		{
			name:      "mis-matched-new-data",
			secretMAC: defaultSecretMAC,
			objMeta:   objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			data: defaultData,
			handleSecretHMAC: handleSecretHMACTest{
				data:    newData,
				wantMAC: newDataHMAC,
			},
			wantErr: assert.NoError,
			want:    false,
		},
		{
			name:      "mis-matched-new-data",
			secretMAC: defaultSecretMAC,
			objMeta:   objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			data: defaultData,
			handleSecretHMAC: handleSecretHMACTest{
				data:    newData,
				wantMAC: newDataHMAC,
			},
			wantErr: assert.NoError,
			want:    false,
		},
		{
			name:    "mismatch-empty-secretMAC",
			objMeta: objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			handleSecretHMAC: handleSecretHMACTest{
				data:    newData,
				wantMAC: newDataHMAC,
			},
			want:    false,
			wantErr: assert.NoError,
		},
		{
			name:    "error-invalid-secretMAC",
			objMeta: objMeta,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			secretMAC: "bbb" + defaultSecretMAC,
			data:      defaultData,
			want:      false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "illegal base64 data at input byte 47", i...)
			},
		},
		{
			name:           "error-invalid-objKind",
			invalidObjKind: true,
			want:           false,
			handleSecretHMAC: handleSecretHMACTest{
				data: defaultData,
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "unsupported object type *v1.Secret", i...)
			},
		},
		{
			name:               "error-no-HMAC-k8s-Secret",
			noCreateHMACSecret: true,
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			secretMAC: defaultSecretMAC,
			handleSecretHMAC: handleSecretHMACTest{
				data: defaultData,
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				if assert.EqualError(t, err, fmt.Sprintf(
					`encountered an error getting %q: secrets "%s" not found`,
					defaultHMACObjKey, defaultHMACObjKey.Name), i...) {
					return assert.True(t, errors.IsNotFound(err))
				}
				return false
			},
		},
		{
			name: "error-invalid-HMAC-key",
			destination: secretsv1beta1.Destination{
				Name:        "baz",
				Create:      false,
				Labels:      nil,
				Annotations: nil,
				Type:        "",
			},
			secretMAC: defaultSecretMAC,
			want:      false,
			hmacKey:   []byte(`bb`),
			handleSecretHMAC: handleSecretHMACTest{
				data: defaultData,
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, `invalid key length 2`, i...)
			},
		},
		{
			name:      "nil-data-error",
			secretMAC: defaultSecretMAC,
			objMeta:   objMeta,
			destination: secretsv1beta1.Destination{
				Name: "baz",
			},
			data: nil,
			handleSecretHMAC: handleSecretHMACTest{
				data:    nil,
				wantMAC: []byte{},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "data for HMAC computation is nil", i...)
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertSecretHMAC(t, tt, testutils.NewFakeClient())
		})
	}
}

// assertSecretHMAC is used to test either HandleSecretHMAC() or
// HMACDestinationSecret().
func assertSecretHMAC(t *testing.T, tt hmacSecretTestCase, c client.Client) {
	t.Helper()

	ctx := context.Background()
	if !tt.noCreateHMACSecret {
		hmacKey := tt.hmacKey
		if len(hmacKey) == 0 {
			hmacKey = defaultHMACKey
		}
		_, err := createHMACKeySecret(ctx, c, defaultHMACObjKey, hmacKey)
		require.NoError(t, err)
	}

	for objKind, obj := range getHMACObjsMap(t, tt) {
		t.Run(tt.name+"_"+objKind, func(t *testing.T) {
			tt.validator = NewHMACValidator(defaultHMACObjKey)
			if tt.destination.Name != "" {
				name := tt.destination.Name + "_" + objKind
				require.NoError(t, c.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: obj.GetNamespace(),
					},
					Data: tt.data,
				}))
			}
			var (
				msg    string
				args   []any
				got    bool
				gotMAC []byte
				err    error
			)
			if len(tt.handleSecretHMAC.data) > 0 || tt.handleSecretHMAC.wantMAC != nil {
				if tt.withTransOpt {
					args = []any{ctx, c, tt.validator, obj, tt.handleSecretHMAC.data, tt.transOpt}
					msg = "HandleSecretHMACWithTransOpt(%v, %v, %v, %v, %v)"
					got, gotMAC, err = HandleSecretHMACWithTransOpt(ctx, c, tt.validator, obj, tt.handleSecretHMAC.data, tt.transOpt)
				} else {
					args = []any{ctx, c, tt.validator, obj, tt.handleSecretHMAC.data, tt.transOpt}
					msg = "HandleSecretHMAC(%v, %v, %v, %v)"
					got, gotMAC, err = HandleSecretHMAC(ctx, c, tt.validator, obj, tt.handleSecretHMAC.data)
				}

				if !tt.wantErr(t, err, fmt.Sprintf(msg, args...)) {
					return
				}

				if err != nil {
					return
				}

				assert.Equalf(t, tt.want, got, msg, args...)
				assert.Equalf(t, tt.handleSecretHMAC.wantMAC, gotMAC, msg, args...)
			} else {
				if tt.withTransOpt {
					msg = "HMACDestinationSecretWithTransOpt(%v, %v, %v, %v, %v)"
					args = []any{ctx, c, tt.validator, obj, tt.handleSecretHMAC.data, tt.transOpt}
					got, err = HMACDestinationSecretWithTransOpt(ctx, c, tt.validator, obj, tt.transOpt)
				} else {
					msg = "HMACDestinationSecret(%v, %v, %v, %v)"
					args = []any{ctx, c, tt.validator, obj, tt.handleSecretHMAC.data}
					got, err = HMACDestinationSecret(ctx, c, tt.validator, obj)
				}
				if !tt.wantErr(t, err, fmt.Sprintf(msg, args...)) {
					return
				}
				assert.Equalf(t, tt.want, got, msg, args...)
			}
		})
	}
}
