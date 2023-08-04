// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

// HandleSecretHMAC compares the HMAC of data to its previously computed value
// stored in o.Status.SecretHMAC, returning true if they are equal. The computed
// new-MAC will be returned so that o.Status.SecretHMAC can be updated.
//
// Supported types for obj are: VaultDynamicSecret, VaultStaticSecret
func HandleSecretHMAC(ctx context.Context, client ctrlclient.Client,
	validator HMACValidator, obj ctrlclient.Object, data map[string][]byte,
) (bool, []byte, error) {
	var cur string
	switch t := obj.(type) {
	case *v1beta1.VaultDynamicSecret:
		cur = t.Status.SecretMAC
	case *v1beta1.VaultStaticSecret:
		cur = t.Status.SecretMAC
	default:
		return false, nil, fmt.Errorf("unsupported object type %T", t)
	}
	logger := log.FromContext(ctx)

	// HMAC the Vault secret data so that it can be compared to the what's in the
	// destination Secret.
	message, err := json.Marshal(data)
	if err != nil {
		return false, nil, err
	}

	newMAC, err := validator.HMAC(ctx, client, message)
	if err != nil {
		return false, nil, err
	}

	// we have never computed the Vault secret data HMAC,
	// so there is no need to perform Secret data drift detection.
	if cur == "" {
		return false, newMAC, nil
	}

	lastMAC, err := base64.StdEncoding.DecodeString(cur)
	if err != nil {
		return false, nil, err
	}

	macsEqual := EqualMACS(lastMAC, newMAC)
	if macsEqual {
		// check to see if the Secret.Data has drifted since the last sync, if it has
		// then it will be overwritten with the Vault secret data this would indicate an
		// out-of-band change made to the Secret's data in this case the controller
		// should do the sync.
		if cur, ok, _ := GetSyncableSecret(ctx, client, obj); ok {
			curMessage, err := json.Marshal(cur.Data)
			if err != nil {
				return false, nil, err
			}

			logger.V(consts.LogLevelDebug).Info(
				"Doing Secret data drift detection", "lastMAC", lastMAC)
			// we only care of the MAC has changed, it's new value is not important here.
			valid, foundMAC, err := validator.Validate(ctx, client, curMessage, lastMAC)
			if err != nil {
				return false, nil, err
			}
			if !valid {
				logger.V(consts.LogLevelDebug).Info("Secret data drift detected",
					"lastMAC", lastMAC, "foundMAC", foundMAC,
					"curMessage", curMessage, "message", message)
			}

			macsEqual = valid
		} else {
			// assume MACs are not equal if the secret does not exist or an error (ignored)
			// has occurred
			macsEqual = false
		}
	}

	return macsEqual, newMAC, nil
}

const (
	HMACKeyName   = "key"
	hmacKeyLength = 16
)

type (
	hmacFromSecretFunc        func(ctx context.Context, client ctrlclient.Client, message []byte) ([]byte, error)
	validateMACFromSecretFunc func(ctx context.Context, client ctrlclient.Client, message, messageMAC []byte) (bool, []byte, error)
)

// used for monkey-patching unit tests
var (
	// always use crypto/rand to ensure that any callers are cryptographically secure.
	randRead  = rand.Read
	EqualMACS = hmac.Equal
)

type HMACValidator interface {
	HMAC(context.Context, ctrlclient.Client, []byte) ([]byte, error)
	Validate(context.Context, ctrlclient.Client, []byte, []byte) (bool, []byte, error)
}

var _ HMACValidator = (*defaultHMACValidator)(nil)

type defaultHMACValidator struct {
	v validateMACFromSecretFunc
	h hmacFromSecretFunc
}

func (v *defaultHMACValidator) Validate(ctx context.Context, client ctrlclient.Client, message, messageMAC []byte) (bool, []byte, error) {
	return v.v(ctx, client, message, messageMAC)
}

func (v *defaultHMACValidator) HMAC(ctx context.Context, client ctrlclient.Client, bytes []byte) ([]byte, error) {
	return v.h(ctx, client, bytes)
}

// CreateHMACKeySecret with a generated HMAC key stored in Secret.Data with HMACKeyName.
// If the Secret already exist, or if the HMAC key could not be generated, an error will be returned.
func CreateHMACKeySecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) (*corev1.Secret, error) {
	key, err := generateHMACKey()
	if err != nil {
		return nil, err
	}

	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      objKey.Name,
			Namespace: objKey.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "vault-secrets-operator",
				"app.kubernetes.io/managed-by": "hashicorp-vso",
				"app.kubernetes.io/component":  "client-cache-storage-verification",
			},
		},
		Immutable: pointer.Bool(true),
		Data: map[string][]byte{
			HMACKeyName: key,
		},
	}

	if err := client.Create(ctx, s); err != nil {
		return nil, err
	}

	return s, nil
}

// GetHMACKeySecret returns the Secret for objKey. The Secret.Data must contain a valid HMAC key for HMACKeyName.
func GetHMACKeySecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) (*corev1.Secret, error) {
	if err := common.ValidateObjectKey(objKey); err != nil {
		return nil, err
	}

	s, err := GetSecret(ctx, client, objKey)
	if err != nil {
		return nil, err
	}

	_, err = validateHMACKeySecret(s)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// getHMACKeyFromSecret returns the HMAC key from Secret for objKey.
func getHMACKeyFromSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) ([]byte, error) {
	s, err := GetHMACKeySecret(ctx, client, objKey)
	if err != nil {
		return nil, err
	}

	return validateHMACKeySecret(s)
}

// newHMACFromSecretFunc returns an hmacFromSecretFunc that can be used to compute a message MAC.
// The objKey must point to a corev1.Secret that holds the HMAC private key.
func newHMACFromSecretFunc(objKey ctrlclient.ObjectKey) hmacFromSecretFunc {
	return func(ctx context.Context, client ctrlclient.Client, message []byte) ([]byte, error) {
		return hmacFromSecret(ctx, client, objKey, message)
	}
}

// newMACValidateFromSecretFunc returns a validateMACFromSecretFunc that can be used to validate the message MAC.
// The objKey must point to a corev1.Secret that holds the HMAC private key.
func newMACValidateFromSecretFunc(objKey ctrlclient.ObjectKey) validateMACFromSecretFunc {
	return func(ctx context.Context, client ctrlclient.Client, message, messageMAC []byte) (bool, []byte, error) {
		return validateMACFromSecret(ctx, client, objKey, message, messageMAC)
	}
}

func NewHMACValidator(objKey ctrlclient.ObjectKey) HMACValidator {
	return &defaultHMACValidator{
		v: newMACValidateFromSecretFunc(objKey),
		h: newHMACFromSecretFunc(objKey),
	}
}

// hmacFromSecret computes the message's HMAC using the HMAC key stored in
// the v1.Secret for objKey.
// Validation of the HMAC can be done with validateMACFromSecret.
func hmacFromSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey,
	message []byte,
) ([]byte, error) {
	key, err := getHMACKeyFromSecret(ctx, client, objKey)
	if err != nil {
		return nil, err
	}
	return MACMessage(key, message)
}

// validateMACFromSecret returns true if the messageMAC matches the HMAC of message.
// The HMAC key is stored in the v1.Secret for objKey.
// Typically, the messageMAC would come from hmacFromSecret.
// Returns false on any error.
func validateMACFromSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey,
	message, messageMAC []byte,
) (bool, []byte, error) {
	key, err := getHMACKeyFromSecret(ctx, client, objKey)
	if err != nil {
		return false, nil, err
	}
	return ValidateMAC(message, messageMAC, key)
}

// validateHMACKeySecret returns the validated key from the Secret.
// Return an error if the Secret does not contain the key, or if the key has
// an invalid length.
func validateHMACKeySecret(s *corev1.Secret) ([]byte, error) {
	var errs error
	key, ok := s.Data[HMACKeyName]
	if !ok {
		errs = errors.Join(errs, fmt.Errorf("secret %s is missing the required field %s", s, HMACKeyName))
	}

	errs = errors.Join(errs, validateKeyLength(key))

	return key, errs
}

// validateKeyLength returns an error if the key's length is not equal to hmacKeyLength.
func validateKeyLength(key []byte) error {
	if len(key) != hmacKeyLength {
		return fmt.Errorf("invalid key length %d", len(key))
	}
	return nil
}

// ValidateMAC computes the MAC of message and compares the result to messageMAC.
// Returns true, along with message MAC, if the two are MACs are equal.
func ValidateMAC(message, messageMAC, key []byte) (bool, []byte, error) {
	expectedMAC, err := MACMessage(key, message)
	if err != nil {
		return false, nil, err
	}

	return EqualMACS(messageMAC, expectedMAC), expectedMAC, nil
}

// MACMessage computes the MAC of data with key.
func MACMessage(key, data []byte) ([]byte, error) {
	if err := validateKeyLength(key); err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(data); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// generateHMACKey for computing HMACs. The key size is 128 bit.
func generateHMACKey() ([]byte, error) {
	key := make([]byte, hmacKeyLength)
	_, err := randRead(key)
	if err != nil {
		return nil, err
	}

	if err := validateKeyLength(key); err != nil {
		return nil, err
	}
	return key, nil
}
