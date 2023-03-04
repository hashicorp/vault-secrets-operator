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

func CreateHKDFSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) (*corev1.Secret, error) {
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
				"app.kubernetes.io/managed-by": "vso",
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

func GetHKDFSecret(ctx context.Context, client ctrlclient.Client, key ctrlclient.ObjectKey) (*corev1.Secret, error) {
	if err := validateObjectKey(key); err != nil {
		return nil, err
	}

	s := &corev1.Secret{}
	if err := client.Get(ctx, key, s); err != nil {
		return nil, err
	}

	_, err := validateHKDFSecret(s)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func validateHKDFSecret(s *corev1.Secret) ([]byte, error) {
	var err error
	key, ok := s.Data[hkdfKeyName]
	if !ok {
		err = errors.Join(fmt.Errorf("secret %s is missing the required field %s", s, hkdfKeyName))
	}

	err = errors.Join(validateKeyLength(key))

	return key, err
}

func validateKeyLength(key []byte) error {
	if len(key) != hkdfKeyLength {
		return fmt.Errorf("invalid key length %d", len(key))
	}
	return nil
}

func validateMAC(message, messageMAC, key []byte) (bool, error) {
	expectedMAC, err := macMessage(key, message)
	if err != nil {
		return false, err
	}

	return hmac.Equal(messageMAC, expectedMAC), nil
}

func macMessage(key, data []byte) ([]byte, error) {
	var err error
	if len(key) != hkdfKeyLength {
		err = errors.Join(fmt.Errorf("invalid key length %d", len(key)))
	}
	err = errors.Join(validateKeyLength(key))
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(data); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

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
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}
	return key, nil
}
