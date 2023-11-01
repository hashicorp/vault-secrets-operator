// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-06-13/client/secret_service"
	"github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-06-13/models"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/utils"
)

const SecretDataKeyRaw = "_raw"

var SecretDataErrorContainsRaw = fmt.Errorf("key '%s' not permitted in Secret data", SecretDataKeyRaw)

// labelOwnerRefUID is used as the primary key when listing the Secrets owned by
// a specific VSO object. It should be included in every Secret that is created
// by VSO.
var labelOwnerRefUID = fmt.Sprintf("%s/vso-ownerRefUID", secretsv1beta1.GroupVersion.Group)

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

// OwnerLabelsForObj returns the canonical set of labels that should be set on
// all secrets created/owned by VSO.
func OwnerLabelsForObj(obj ctrlclient.Object) (map[string]string, error) {
	uid := string(obj.GetUID())
	if uid == "" {
		return nil, fmt.Errorf("object %q has an empty UID", ctrlclient.ObjectKeyFromObject(obj))
	}

	l := make(map[string]string)
	for k, v := range OwnerLabels {
		l[k] = v
	}
	l[labelOwnerRefUID] = uid

	return l, nil
}

func matchingLabelsForObj(obj ctrlclient.Object) (ctrlclient.MatchingLabels, error) {
	m := ctrlclient.MatchingLabels{}
	l, err := OwnerLabelsForObj(obj)
	if err != nil {
		return m, err
	}
	if string(obj.GetUID()) == "" {
		return m, fmt.Errorf("object %q has an empty UID", ctrlclient.ObjectKeyFromObject(obj))
	}

	for k, v := range l {
		m[k] = v
	}
	m[labelOwnerRefUID] = string(obj.GetUID())

	return m, nil
}

// FindSecretsOwnedByObj returns all corev1.Secrets that are owned by obj.
// Those are secrets that have a copy of OwnerLabels, and exactly one metav1.OwnerReference
// that matches obj.
func FindSecretsOwnedByObj(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) ([]corev1.Secret, error) {
	ownerRef, err := utils.GetOwnerRefFromObj(obj, client.Scheme())
	if err != nil {
		return nil, err
	}

	matchingLabels, err := matchingLabelsForObj(obj)
	if err != nil {
		return nil, err
	}

	secrets := &corev1.SecretList{}
	if err := client.List(ctx, secrets,
		matchingLabels, ctrlclient.InNamespace(obj.GetNamespace())); err != nil {
		return nil, err
	}

	var result []corev1.Secret
	for _, s := range secrets.Items {
		if err := checkSecretIsOwnedByObj(&s, []metav1.OwnerReference{ownerRef}); err == nil {
			result = append(result, s)
		}
	}

	return result, nil
}

func DefaultSyncOptions() SyncOptions {
	return SyncOptions{
		PruneOrphans: true,
	}
}

// SyncOptions to provide to SyncSecret().
type SyncOptions struct {
	// PruneOrphans controls whether to delete any previously synced k8s Secrets.
	PruneOrphans bool
}

// SyncSecret writes data to a Kubernetes Secret for obj. All configuring is
// derived from the object's Spec.Destination configuration. Note: in order to
// keep the interface simpler opts is a variadic argument, only the first element
// of opts will ever be used.
//
// See NewSyncableSecretMetaData for the supported types for obj.
func SyncSecret(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, data map[string][]byte, opts ...SyncOptions) error {
	var options SyncOptions
	if len(opts) > 0 {
		options = opts[0]
	} else {
		options = DefaultSyncOptions()
	}

	meta, err := common.NewSyncableSecretMetaData(obj)
	if err != nil {
		return err
	}

	logger := log.FromContext(ctx).WithName("syncSecret").WithValues(
		"secretName", meta.Destination.Name, "create", meta.Destination.Create)
	key := ctrlclient.ObjectKey{
		Namespace: obj.GetNamespace(),
		Name:      meta.Destination.Name,
	}

	if err := common.ValidateObjectKey(key); err != nil {
		return fmt.Errorf("invalid Destination, err=%w", err)
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

	pruneOrphans := func() {
		if options.PruneOrphans {
			// for now we treat orphan pruning errors as being non-fatal.
			if err := pruneOrphanSecrets(ctx, client, obj, meta.Destination); err != nil {
				logger.V(consts.LogLevelWarning).Error(err, "Failed to prune orphan secrets",
					"owner", ctrlclient.ObjectKeyFromObject(obj).String())
			} else {
				logger.V(consts.LogLevelDebug).Info("Successfully pruned all orphan secrets",
					"owner", ctrlclient.ObjectKeyFromObject(obj).String())
			}
		}
	}

	// not configured to create the destination Secret
	if !meta.Destination.Create {
		if !exists {
			return fmt.Errorf("destination secret %s does not exist, and create=%t",
				key, meta.Destination.Create)
		}

		// it's probably best that we don't add labels nor annotations when we are not the Secret's owner.
		// It will make cleaning up previous labels/annotation additions difficult,  since we don't know
		// what we set previously. It is possible to keep the previous labels/annotations in the
		// syncable-secret's Status, but...
		dest.Data = data
		logger.V(consts.LogLevelDebug).Info("Updating secret")
		if err := client.Update(ctx, &dest); err != nil {
			return err
		}

		pruneOrphans()

		return nil
	}

	// we are responsible for the Secret's complete lifecycle
	secretType := corev1.SecretTypeOpaque
	if meta.Destination.Type != "" {
		secretType = meta.Destination.Type
	}

	// these are the OwnerReferences that should be included in any Secret that is created/owned by
	// the syncable-secret
	references := []metav1.OwnerReference{
		{
			APIVersion: meta.APIVersion,
			Kind:       meta.Kind,
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
				Name:      meta.Destination.Name,
				Namespace: obj.GetNamespace(),
			},
		}
		logger.V(consts.LogLevelDebug).Info("Creating new secret",
			"secret", ctrlclient.ObjectKeyFromObject(&dest))
	}

	// common setup/updates
	// set any labels configured in meta.Destination.Labels
	labels := make(map[string]string)
	for k, v := range meta.Destination.Labels {
		labels[k] = v
	}

	ownerLabels, err := OwnerLabelsForObj(obj)
	// always add the "owner" labels last to guard against intersections with meta.Destination.Labels
	for k, v := range ownerLabels {
		_, ok := labels[k]
		if ok {
			logger.V(consts.LogLevelWarning).Info(
				"Label conflicts with a default owner label, owner label takes precedence",
				"label", k)
		}
		labels[k] = v
	}
	// add any annotations configured in meta.Destination.Labels
	dest.Data = data
	dest.Type = secretType
	dest.SetAnnotations(meta.Destination.Annotations)
	dest.SetLabels(labels)
	dest.SetOwnerReferences(references)

	if exists {
		logger.V(consts.LogLevelDebug).Info("Updating secret")
		if err := client.Update(ctx, &dest); err != nil {
			return err
		}
	} else {
		logger.V(consts.LogLevelDebug).Info("Creating secret")
		if err := client.Create(ctx, &dest); err != nil {
			return err
		}
	}

	pruneOrphans()

	return nil
}

func pruneOrphanSecrets(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, dest *secretsv1beta1.Destination) error {
	owned, err := FindSecretsOwnedByObj(ctx, client, obj)
	if err != nil {
		return err
	}

	var errs error
	for _, s := range owned {
		if s.Name == dest.Name {
			continue
		}
		if err := client.Delete(ctx, &s); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

// CheckSecretExists checks if the Secret configured on obj exists.
// Returns true if the secret exists, false if the secret was not found.
// If any error, other than apierrors.IsNotFound, is encountered,
// then that error will be returned along with the existence value of false.
//
// See NewSyncableSecretMetaData for the supported types for obj.
func CheckSecretExists(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (bool, error) {
	_, ok, err := getSecretExists(ctx, client, obj)
	return ok, err
}

// GetSyncableSecret returns K8s Secret for obj.
func GetSyncableSecret(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (*corev1.Secret, bool, error) {
	return getSecretExists(ctx, client, obj)
}

func getSecretExists(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (*corev1.Secret, bool, error) {
	meta, err := common.NewSyncableSecretMetaData(obj)
	if err != nil {
		return nil, false, err
	}

	logger := log.FromContext(ctx).WithName("syncSecret").WithValues(
		"secretName", meta.Destination.Name, "create", meta.Destination.Create)
	objKey := ctrlclient.ObjectKey{Namespace: obj.GetNamespace(), Name: meta.Destination.Name}
	s, err := GetSecret(ctx, client, objKey)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(consts.LogLevelDebug).Info("Secret does not exist")
			return nil, false, nil
		}
		// let the caller log the error
		return nil, false, err
	}

	logger.V(consts.LogLevelDebug).Info("Secret exists")
	return s, true, nil
}

func GetSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) (*corev1.Secret, error) {
	var s corev1.Secret
	err := client.Get(ctx, objKey, &s)

	return &s, err
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
			errs = errors.Join(errs, fmt.Errorf(
				"invalid owner label, key=%s, present=%t", k, ok))
		}
	}
	// check that obj is the Secret's true Owner
	if len(dest.OwnerReferences) > 0 {
		if !equality.Semantic.DeepEqual(dest.OwnerReferences, references) {
			// we are not the owner, perhaps another syncable-secret resource owns this secret?
			errs = errors.Join(errs, fmt.Errorf("invalid ownerReferences, refs=%#v", dest.OwnerReferences))
		}
	} else {
		errs = errors.Join(errs, fmt.Errorf("secret %s has no ownerReferences", key))
	}
	if errs != nil {
		errs = errors.Join(errs, fmt.Errorf("not the owner of the destination Secret %s", key))
	}
	return errs
}

// SecretDataBuilder constructs K8s Secret data from various sources.
type SecretDataBuilder struct{}

// WithVaultData returns the K8s Secret data from a Vault Secret data.
func (s *SecretDataBuilder) WithVaultData(d, raw map[string]any, opt *SecretRenderOption) (map[string][]byte, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}

	data := make(map[string][]byte)
	if opt != nil {
		if len(opt.Specs) > 0 {
			metadata, ok := raw["metadata"].(map[string]any)
			if !ok {
				metadata = make(map[string]any)
			}

			input := NewSecretInput(d, metadata)
			data, err = renderTemplates(opt, input)
			if err != nil {
				return nil, err
			}
		}

		filtered, err := filterFields(&opt.FieldFilter, d)
		if err != nil {
			return nil, err
		}

		// include the filtered non-templated fields.
		for k, v := range filtered {
			if _, ok := data[k]; !ok {
				bv, err := marshalJSON(v)
				if err != nil {
					return nil, err
				}
				data[k] = bv
			}
		}

	} else {
		for k, v := range d {
			b, err := marshalJSON(v)
			if err != nil {
				return nil, err
			}

			data[k] = b
		}
	}

	return s.makeData(b, data)
}

func marshalJSON(value any) ([]byte, error) {
	var b []byte
	var err error
	switch x := value.(type) {
	case string:
		b = []byte(x)
	default:
		b, err = json.Marshal(value)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// WithHVSAppSecrets returns the K8s Secret data from HCP Vault Secrets App.
func (s *SecretDataBuilder) WithHVSAppSecrets(resp *hvsclient.OpenAppSecretsOK, opt *SecretRenderOption) (map[string][]byte, error) {
	p := resp.GetPayload()
	raw, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}

	withOpt := opt != nil
	withSpecs := withOpt && len(opt.Specs) > 0
	var secrets map[string]any
	var metadata map[string]any
	if withOpt {
		// secrets for SecretInput
		secrets = make(map[string]any)
		// metadata for SecretInput
		metadata = make(map[string]any)
	}
	// secret data returned to the caller
	data := make(map[string][]byte)
	for _, v := range p.Secrets {
		ver := v.Version
		if ver == nil {
			continue
		}

		if ver.Type != "kv" {
			continue
		}

		if !withOpt {
			// no input data processing required
			data[v.Name] = []byte(ver.Value)
		} else {
			if withSpecs {
				bv, err := v.MarshalBinary()
				if err != nil {
					return nil, err
				}
				// unmarshal to non-open secret, which should/must not contain any
				// secret/confidential data.
				var ss models.Secrets20230613Secret
				if err := json.Unmarshal(bv, &ss); err != nil {
					return nil, err
				}

				sv, err := ss.MarshalBinary()
				if err != nil {
					return nil, err
				}

				// unmarshal to
				var m map[string]any
				if err := json.Unmarshal(sv, &m); err != nil {
					return nil, err
				}

				// maps secret name to its secret metadata
				metadata[v.Name] = m
			}
			// populate secrets for filtering and template processing below
			secrets[v.Name] = ver.Value
		}
	}

	if withOpt {
		if withSpecs {
			data, err = renderTemplates(opt, NewSecretInput(secrets, metadata))
			if err != nil {
				return nil, err
			}
		}

		if filtered, err := filterFields(&opt.FieldFilter, secrets); err != nil {
			return nil, err
		} else {
			for k, v := range filtered {
				// include only non-templated fields.
				if _, ok := data[k]; !ok {
					b, err := marshalJSON(v)
					if err != nil {
						return nil, err
					}
					data[k] = b
				}
			}
		}
	}

	return s.makeData(raw, data)
}

func (s *SecretDataBuilder) makeData(raw []byte, data map[string][]byte) (map[string][]byte, error) {
	if _, ok := data[SecretDataKeyRaw]; ok {
		return nil, SecretDataErrorContainsRaw
	}

	data[SecretDataKeyRaw] = raw

	return data, nil
}

func NewSecretsDataBuilder() *SecretDataBuilder {
	return &SecretDataBuilder{}
}
