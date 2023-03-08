// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

// OwnerLabels will be applied to any k8s secret we create. They are used in Secret ownership checks.
// There are similar labels in the vault package. It's important that component secret's value never
// intersects with that of other components of the system, since this could lead to data loss.
//
// Make OwnerLabels public so that they can be accessed from tests.
var OwnerLabels = map[string]string{
	"app.kubernetes.io/name":       "vault-secrets-operator",
	"app.kubernetes.io/managed-by": "hashicorp-vso",
	"app.kubernetes.io/component":  "secret-sync",
}

// syncableSecretMetaData provides common data structure that extracts the bits pertinent handling
// any of the sync-able secret custom resource types.
//
// See newSyncableSecretMetaData for the supported object types.
type syncableSecretMetaData struct {
	apiVersion string
	kind       string
	destConfig *secretsv1alpha1.Destination
}

// newSyncableSecretMetaData returns syncableSecretMetaData if obj is a supported type.
// An error will be returned of obj is not a supported type.
//
// Supported types for obj are: VaultDynamicSecret, VaultStaticSecret. VaultPKISecret
func newSyncableSecretMetaData(obj ctrlclient.Object) (*syncableSecretMetaData, error) {
	switch t := obj.(type) {
	case *secretsv1alpha1.VaultDynamicSecret:
		return &syncableSecretMetaData{
			destConfig: &t.Spec.Destination,
			apiVersion: t.APIVersion,
			kind:       t.Kind,
		}, nil
	case *secretsv1alpha1.VaultStaticSecret:
		return &syncableSecretMetaData{
			destConfig: &t.Spec.Destination,
			apiVersion: t.APIVersion,
			kind:       t.Kind,
		}, nil
	case *secretsv1alpha1.VaultPKISecret:
		return &syncableSecretMetaData{
			destConfig: &t.Spec.Destination,
			apiVersion: t.APIVersion,
			kind:       t.Kind,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", t)
	}
}

// SyncSecret writes data to a Kubernetes Secret for obj. All configuring is derived from the object's
// Spec.Destination configuration.
//
// See newSyncableSecretMetaData for the supported types for obj.
func SyncSecret(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, data map[string][]byte) error {
	meta, err := newSyncableSecretMetaData(obj)
	if err != nil {
		return err
	}

	logger := log.FromContext(ctx).WithName("syncSecret").WithValues(
		"secretName", meta.destConfig.Name, "create", meta.destConfig.Create)
	key := ctrlclient.ObjectKey{
		Namespace: obj.GetNamespace(),
		Name:      meta.destConfig.Name,
	}

	var dest corev1.Secret
	exists := true
	if err := client.Get(ctx, key, &dest); err != nil {
		if apierrors.IsNotFound(err) {
			exists = false
		} else {
			return err
		}
	}

	// not configured to create the destination Secret
	if !meta.destConfig.Create {
		if !exists {
			return fmt.Errorf("destination secret %s does not exist, and create=%t",
				key, meta.destConfig.Create)
		}

		// it's probably best that we don't add labels nor annotations when we are not the Secret's owner.
		// It will make cleaning up previous labels/annotation additions difficult,  since we don't know
		// what we set previously. It is possible to keep the previous labels/annotations in the
		// syncable-secret's Status, but...
		dest.Data = data
		logger.V(consts.LogLevelDebug).Info("Updating secret")
		return client.Update(ctx, &dest)
	}

	// we are responsible for the Secret's complete lifecycle
	secretType := corev1.SecretTypeOpaque
	if meta.destConfig.Type != "" {
		secretType = meta.destConfig.Type
	}

	// these are the OwnerReferences that should be included in any Secret that is created/owned by
	// the syncable-secret
	references := []metav1.OwnerReference{
		{
			APIVersion: meta.apiVersion,
			Kind:       meta.kind,
			Name:       obj.GetName(),
			UID:        obj.GetUID(),
		},
	}
	if exists {
		logger.V(consts.LogLevelDebug).Info("Found pre-existing secret",
			"secret", ctrlclient.ObjectKeyFromObject(&dest))
		if err := checkSecretIsOwnedByObj(&dest, references); err != nil {
			return err
		}

	} else {
		// secret does not exist, so we are going to create it.
		dest = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      meta.destConfig.Name,
				Namespace: obj.GetNamespace(),
			},
		}
		logger.V(consts.LogLevelDebug).Info("Creating new secret",
			"secret", ctrlclient.ObjectKeyFromObject(&dest))
	}

	// common setup/updates
	// set any labels configured in destConfig.Labels
	labels := make(map[string]string)
	for k, v := range meta.destConfig.Labels {
		labels[k] = v
	}
	// always add the "owner" labels last to guard against intersections with destConfig.Labels
	for k, v := range OwnerLabels {
		labels[k] = v
	}
	// add any annotations configured in destConfig.Labels
	dest.Data = data
	dest.Type = secretType
	dest.SetAnnotations(meta.destConfig.Annotations)
	dest.SetLabels(labels)
	dest.SetOwnerReferences(references)

	if exists {
		logger.V(consts.LogLevelDebug).Info("Updating secret")
		return client.Update(ctx, &dest)
	}

	logger.V(consts.LogLevelDebug).Info("Creating secret")
	return client.Create(ctx, &dest)
}

// CheckSecretExists checks if the Secret configured on obj exists.
// Returns true if the secret exists, false if the secret was not found.
// If any error, other than apierrors.IsNotFound, is encountered,
// then that error will be returned along with the existence value of false.
//
// See newSyncableSecretMetaData for the supported types for obj.
func CheckSecretExists(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (bool, error) {
	meta, err := newSyncableSecretMetaData(obj)
	if err != nil {
		return false, err
	}

	logger := log.FromContext(ctx).WithName("syncSecret").WithValues(
		"secretName", meta.destConfig.Name, "create", meta.destConfig.Create)
	key := ctrlclient.ObjectKey{Namespace: obj.GetNamespace(), Name: meta.destConfig.Name}
	var s corev1.Secret
	if err := client.Get(ctx, key, &s); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(consts.LogLevelDebug).Info("Secret does not exist")
			return false, nil
		}
		// let the caller log the error
		return false, err
	}

	logger.V(consts.LogLevelDebug).Info("Secret exists")
	return true, nil
}

// checkSecretIsOwnedByObj validates the Secret is owned by obj by checking its Labels and OwnerReferences.
func checkSecretIsOwnedByObj(dest *corev1.Secret, references []metav1.OwnerReference) error {
	var errs error
	// checking for Secret ownership relies on first checking the Secret's labels,
	// then verifying that its OwnerReferences match the SyncableSecret.

	// check that all owner labels are present and valid, if not return an error
	// this may cause issues if we ever add new "owner" labels, but for now this check should be good enough.
	key := ctrlclient.ObjectKeyFromObject(dest)
	for k, v := range OwnerLabels {
		if o, ok := dest.Labels[k]; o != v || !ok {
			errs = errors.Join(errs, fmt.Errorf("invalid owner label, key=%s, present=%t", key, ok))
		}
	}
	// check that obj is the Secret's true Owner
	if len(dest.OwnerReferences) > 0 && !equality.Semantic.DeepEqual(dest.OwnerReferences, references) {
		// we are not the owner, perhaps another syncable-secret resource owns this secret?
		errs = errors.Join(errs, fmt.Errorf("invalid ownerReferences, refs=%#v", dest.OwnerReferences))
	}
	if errs != nil {
		errs = errors.Join(errs, fmt.Errorf("not the owner of the destination Secret %s", key))
	}
	return errs
}
