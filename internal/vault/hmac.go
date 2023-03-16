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
	"io"

	"golang.org/x/crypto/hkdf"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	hkdfKeyName   = "key"
	hkdfKeyLength = 16
)

type (
	HMACFromHKDFSecretFunc        func(ctx context.Context, client ctrlclient.Client, message []byte) ([]byte, error)
	ValidateMACFromHKDFSecretFunc func(ctx context.Context, client ctrlclient.Client, message, messageMAC []byte) (bool, []byte, error)
)

// used for monkey-patching unit tests
var (
	ioReadFull = io.ReadFull
	EqualMACS  = hmac.Equal
)

// createHKDFSecret with a generated HKDF key stored in Secret.Data with hkdfKeyName.
// If the Secret already exist, or if the HKDF key could not be generated, an error will be returned.
func createHKDFSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) (*corev1.Secret, error) {
	key, err := generateHKDFKey()
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
			hkdfKeyName: key,
		},
	}

	if err := client.Create(ctx, s); err != nil {
		return nil, err
	}

	return s, nil
}

// getHKDFSecret returns the Secret for objKey. The Secret.Data must contain a valid HKDF key for hkdfKeyName.
func getHKDFSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) (*corev1.Secret, error) {
	if err := validateObjectKey(objKey); err != nil {
		return nil, err
	}

	s := &corev1.Secret{}
	if err := client.Get(ctx, objKey, s); err != nil {
		return nil, err
	}

	_, err := validateHKDFSecret(s)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// getKeyFromHKDFSecret returns the HKDF key from Secret for objKey.
func getKeyFromHKDFSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) ([]byte, error) {
	s, err := getHKDFSecret(ctx, client, objKey)
	if err != nil {
		return nil, err
	}

	return validateHKDFSecret(s)
}

// NewHMACFromHKDFSecretFunc returns an HMACFromHKDFSecretFunc that can be used to compute a message MAC.
// The objKey must point to a corev1.Secret that holds the HKDF private key.
func NewHMACFromHKDFSecretFunc(objKey ctrlclient.ObjectKey) HMACFromHKDFSecretFunc {
	return func(ctx context.Context, client ctrlclient.Client, message []byte) ([]byte, error) {
		return hmacFromHKDFSecret(ctx, client, objKey, message)
	}
}

// NewMACValidateFromHKDFSecretFunc returns a ValidateMACFromHKDFSecretFunc that can be used to validate the message MAC.
// The objKey must point to a corev1.Secret that holds the HKDF private key.
func NewMACValidateFromHKDFSecretFunc(objKey ctrlclient.ObjectKey) ValidateMACFromHKDFSecretFunc {
	return func(ctx context.Context, client ctrlclient.Client, message, messageMAC []byte) (bool, []byte, error) {
		return validateMACFromHKDFSecret(ctx, client, objKey, message, messageMAC)
	}
}

// hmacFromHKDFSecret computes the message's HMAC using the HKDF key stored in
// the v1.Secret for objKey.
// Validation of the HMAC can be done with validateMACFromHKDFSecret.
func hmacFromHKDFSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey,
	message []byte,
) ([]byte, error) {
	key, err := getKeyFromHKDFSecret(ctx, client, objKey)
	if err != nil {
		return nil, err
	}
	return macMessage(key, message)
}

// validateMACFromHKDFSecret returns true if the messageMAC matches the HMAC of message.
// The HKDF key is stored in the v1.Secret for objKey.
// Typically, the messageMAC would come from hmacFromHKDFSecret.
// Returns false on any error.
func validateMACFromHKDFSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey,
	message, messageMAC []byte,
) (bool, []byte, error) {
	key, err := getKeyFromHKDFSecret(ctx, client, objKey)
	if err != nil {
		return false, nil, err
	}
	return validateMAC(message, messageMAC, key)
}

// validateHKDFSecret returns the validated HKDF key from the Secret.
// Return an error if the Secret does not contain the key, or if the key has
// an invalid length.
func validateHKDFSecret(s *corev1.Secret) ([]byte, error) {
	var errs error
	key, ok := s.Data[hkdfKeyName]
	if !ok {
		errs = errors.Join(errs, fmt.Errorf("secret %s is missing the required field %s", s, hkdfKeyName))
	}

	errs = errors.Join(errs, validateKeyLength(key))

	return key, errs
}

// validateKeyLength returns an error if the HKDF key's length is not equal to hkdfKeyLength.
func validateKeyLength(key []byte) error {
	if len(key) != hkdfKeyLength {
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

// generateHKDFKey for computing HMACs.
func generateHKDFKey() ([]byte, error) {
	hash := sha256.New
	salt := make([]byte, hash().Size())
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	secret := make([]byte, hash().Size()*2)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	kdf := hkdf.New(hash, secret, salt, nil)
	key := make([]byte, hkdfKeyLength)
	if _, err := ioReadFull(kdf, key); err != nil {
		return nil, err
	}

	if err := validateKeyLength(key); err != nil {
		return nil, err
	}
	return key, nil
}
