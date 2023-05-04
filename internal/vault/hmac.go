// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/hashicorp/vault-secrets-operator/internal/common"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	hmacKeyName   = "key"
	hmacKeyLength = 16
)

type (
	HMACFromSecretFunc        func(ctx context.Context, client ctrlclient.Client, message []byte) ([]byte, error)
	ValidateMACFromSecretFunc func(ctx context.Context, client ctrlclient.Client, message, messageMAC []byte) (bool, []byte, error)
)

// used for monkey-patching unit tests
var (
	// always use crypto/rand to ensure that any callers are cryptographically secure.
	randRead  = rand.Read
	EqualMACS = hmac.Equal
)

// createHMACKeySecret with a generated HMAC key stored in Secret.Data with hmacKeyName.
// If the Secret already exist, or if the HMAC key could not be generated, an error will be returned.
func createHMACKeySecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) (*corev1.Secret, error) {
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
			hmacKeyName: key,
		},
	}

	if err := client.Create(ctx, s); err != nil {
		return nil, err
	}

	return s, nil
}

// getHMACKeySecret returns the Secret for objKey. The Secret.Data must contain a valid HMAC key for hmacKeyName.
func getHMACKeySecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) (*corev1.Secret, error) {
	if err := common.ValidateObjectKey(objKey); err != nil {
		return nil, err
	}

	s := &corev1.Secret{}
	if err := client.Get(ctx, objKey, s); err != nil {
		return nil, err
	}

	_, err := validateHMACKeySecret(s)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// getHMACKeyFromSecret returns the HMAC key from Secret for objKey.
func getHMACKeyFromSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) ([]byte, error) {
	s, err := getHMACKeySecret(ctx, client, objKey)
	if err != nil {
		return nil, err
	}

	return validateHMACKeySecret(s)
}

// NewHMACFromSecretFunc returns an HMACFromSecretFunc that can be used to compute a message MAC.
// The objKey must point to a corev1.Secret that holds the HMAC private key.
func NewHMACFromSecretFunc(objKey ctrlclient.ObjectKey) HMACFromSecretFunc {
	return func(ctx context.Context, client ctrlclient.Client, message []byte) ([]byte, error) {
		return hmacFromSecret(ctx, client, objKey, message)
	}
}

// NewMACValidateFromSecretFunc returns a ValidateMACFromSecretFunc that can be used to validate the message MAC.
// The objKey must point to a corev1.Secret that holds the HMAC private key.
func NewMACValidateFromSecretFunc(objKey ctrlclient.ObjectKey) ValidateMACFromSecretFunc {
	return func(ctx context.Context, client ctrlclient.Client, message, messageMAC []byte) (bool, []byte, error) {
		return validateMACFromSecret(ctx, client, objKey, message, messageMAC)
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
	return macMessage(key, message)
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
	return validateMAC(message, messageMAC, key)
}

// validateHMACKeySecret returns the validated key from the Secret.
// Return an error if the Secret does not contain the key, or if the key has
// an invalid length.
func validateHMACKeySecret(s *corev1.Secret) ([]byte, error) {
	var errs error
	key, ok := s.Data[hmacKeyName]
	if !ok {
		errs = errors.Join(errs, fmt.Errorf("secret %s is missing the required field %s", s, hmacKeyName))
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

// validateMAC computes the MAC of message and compares the result to messageMAC.
// Returns true, along with message MAC, if the two are MACs are equal.
func validateMAC(message, messageMAC, key []byte) (bool, []byte, error) {
	expectedMAC, err := macMessage(key, message)
	if err != nil {
		return false, nil, err
	}

	return EqualMACS(messageMAC, expectedMAC), expectedMAC, nil
}

// macMessage computes the MAC of data with key.
func macMessage(key, data []byte) ([]byte, error) {
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
