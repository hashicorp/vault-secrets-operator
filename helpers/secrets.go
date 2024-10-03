// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/client/secret_service"
	"github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/models"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/utils"
)

const (
	SecretDataKeyRaw      = "_raw"
	HVSSecretTypeKV       = "kv"
	HVSSecretTypeRotating = "rotating"
	HVSSecretTypeDynamic  = "dynamic"
)

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

	dest, exists, err := getSecretExists(ctx, client, key)
	if err != nil {
		return err
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
		if err := client.Update(ctx, dest); err != nil {
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
			"secret", ctrlclient.ObjectKeyFromObject(dest))

		checkOwnerShip := true
		if meta.Destination.Overwrite {
			checkOwnerShip = HasOwnerLabels(dest)
		}

		if checkOwnerShip {
			if err := checkSecretIsOwnedByObj(dest, references); err != nil {
				return err
			}
		}
	} else {
		// secret does not exist, so we are going to create it.
		dest = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      meta.Destination.Name,
				Namespace: obj.GetNamespace(),
			},
		}
		logger.V(consts.LogLevelDebug).Info("Creating new secret",
			"secret", ctrlclient.ObjectKeyFromObject(dest))
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

	lastType := dest.Type
	dest.Data = data
	dest.Type = secretType
	dest.SetAnnotations(meta.Destination.Annotations)
	dest.SetLabels(labels)
	dest.SetOwnerReferences(references)
	logger.V(consts.LogLevelTrace).Info("ObjectMeta", "objectMeta", dest.ObjectMeta)
	if exists {
		// secret type is immutable, so we need to force recreate the secret when the
		// type changes.
		if dest.Type != lastType {
			logger.V(consts.LogLevelDebug).Info("Recreating secret")
			// unset the labels so that the owner object does not get enqueued on secret
			// deletion
			dest.Type = lastType
			dest.SetLabels(nil)
			if err := client.Update(ctx, dest); err != nil {
				return err
			}

			// delete the secret
			if err := client.Delete(ctx, dest); err != nil {
				return err
			}

			dest.Type = secretType
			dest.ResourceVersion = ""
			dest.Generation = 0
			dest.SetLabels(labels)
			if err := client.Create(ctx, dest); err != nil {
				return err
			}
		} else {
			logger.V(consts.LogLevelDebug).Info("Updating secret")
			if err := client.Update(ctx, dest); err != nil {
				return err
			}
		}
	} else {
		logger.V(consts.LogLevelDebug).Info("Creating secret")
		if err := client.Create(ctx, dest); err != nil {
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
	_, ok, err := getSecretExistsForObj(ctx, client, obj)
	return ok, err
}

// GetSyncableSecret returns K8s Secret for obj.
func GetSyncableSecret(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (*corev1.Secret, bool, error) {
	return getSecretExistsForObj(ctx, client, obj)
}

func getSecretExistsForObj(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (*corev1.Secret, bool, error) {
	meta, err := common.NewSyncableSecretMetaData(obj)
	if err != nil {
		return nil, false, err
	}

	logger := log.FromContext(ctx).WithName("syncSecret").WithValues(
		"secretName", meta.Destination.Name, "create", meta.Destination.Create)
	objKey := ctrlclient.ObjectKey{Namespace: obj.GetNamespace(), Name: meta.Destination.Name}
	s, exists, err := getSecretExists(ctx, client, objKey)
	if err != nil {
		// let the caller log the error
		return nil, false, err
	}

	logger.V(consts.LogLevelDebug).Info("Secret exists")
	return s, exists, nil
}

func GetSecret(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) (*corev1.Secret, error) {
	var s corev1.Secret
	err := client.Get(ctx, objKey, &s)

	return &s, err
}

func getSecretExists(ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) (*corev1.Secret, bool, error) {
	s, err := GetSecret(ctx, client, objKey)
	var exists bool
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = nil
		}
	} else {
		exists = true
	}
	return s, exists, err
}

// HasOwnerLabels returns true if all owner labels are present and valid, if not
// it returns false.
// Note: this may cause issues if we ever add new "owner"
// labels, but for now this check should be good enough.
func HasOwnerLabels(o ctrlclient.Object) bool {
	return CheckOwnerLabels(o) == nil
}

// CheckOwnerLabels checks that all owner labels are present and valid.
// Note: this may cause issues if we ever add new "owner" labels,
// but for now this check should be good enough.
func CheckOwnerLabels(o ctrlclient.Object) error {
	// check that all owner labels are present and valid, if not return an error
	// this may cause issues if we ever add new "owner" labels, but for now this check should be good enough.
	var errs error

	labels := o.GetLabels()
	for k, v := range OwnerLabels {
		if o, ok := labels[k]; o != v || !ok {
			errs = errors.Join(errs, fmt.Errorf(
				"invalid owner label, key=%s, present=%t", k, ok))
		}
	}

	return errs
}

// checkSecretIsOwnedByObj validates the Secret is owned by obj by checking its Labels and OwnerReferences.
func checkSecretIsOwnedByObj(dest *corev1.Secret, references []metav1.OwnerReference) error {
	// checking for Secret ownership relies on first checking the Secret's labels,
	// then verifying that its OwnerReferences match the SyncableSecret.

	// check that all owner labels are present and valid, if not return an error
	// this may cause issues if we ever add new "owner" labels, but for now this check should be good enough.

	errs := CheckOwnerLabels(dest)
	key := ctrlclient.ObjectKeyFromObject(dest)
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

// CreateOrUpdateSecret creates a k8s secret if it doesn't exist, or updates an
// existing secret.
func CreateOrUpdateSecret(ctx context.Context, client ctrlclient.Client, dest *corev1.Secret) error {
	objKey := ctrlclient.ObjectKeyFromObject(dest)
	_, exists, err := getSecretExists(ctx, client, objKey)
	if err != nil {
		return err
	}
	if exists {
		return client.Update(ctx, dest)
	}
	return client.Create(ctx, dest)
}

// DeleteSecret deletes a k8s secret, returning nil if the secret doesn't exist.
func DeleteSecret(ctx context.Context, client ctrlclient.Client, objKey client.ObjectKey) error {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      objKey.Name,
			Namespace: objKey.Namespace,
		},
	}
	err := client.Delete(ctx, s)
	if err != nil && apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// SecretDataBuilder constructs K8s Secret data from various sources.
type SecretDataBuilder struct{}

// WithVaultData returns the K8s Secret data from a Vault Secret data.
func (s *SecretDataBuilder) WithVaultData(d, secretData map[string]any, opt *SecretTransformationOption) (map[string][]byte, error) {
	if opt == nil {
		opt = &SecretTransformationOption{}
	}

	raw, err := json.Marshal(secretData)
	if err != nil {
		return nil, err
	}

	data := make(map[string][]byte)
	if len(opt.KeyedTemplates) > 0 {
		metadata, ok := secretData["metadata"].(map[string]any)
		if !ok {
			metadata = make(map[string]any)
		}

		input := NewSecretInput(d, metadata, opt.Annotations, opt.Labels)
		data, err = renderTemplates(opt, input)
		if err != nil {
			return nil, err
		}
	}

	return makeK8sData(d, data, raw, opt)
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
func (s *SecretDataBuilder) WithHVSAppSecrets(resp *hvsclient.OpenAppSecretsOK, opt *SecretTransformationOption) (map[string][]byte, error) {
	if opt == nil {
		opt = &SecretTransformationOption{}
	}

	p := resp.GetPayload()
	raw, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// secrets for SecretInput
	secrets := make(map[string]any)
	// metadata for SecretInput
	metadata := make(map[string]any)
	// secret data returned to the caller
	data := make(map[string][]byte)
	hasTemplates := len(opt.KeyedTemplates) > 0
	for _, v := range p.Secrets {
		if v.StaticVersion == nil && v.RotatingVersion == nil && v.DynamicInstance == nil {
			continue
		}

		switch v.Type {
		case HVSSecretTypeKV:
			secrets[v.Name] = v.StaticVersion.Value
		case HVSSecretTypeRotating:
			if v.RotatingVersion == nil {
				return nil, fmt.Errorf("rotating secret %s has no RotatingVersion", v.Name)
			}
			// Since rotating secrets have multiple values, prefix each key with
			// the secret name to avoid collisions.
			for rotatingKey, rotatingValue := range v.RotatingVersion.Values {
				prefixedKey := fmt.Sprintf("%s_%s", v.Name, rotatingKey)
				secrets[prefixedKey] = rotatingValue
			}

			vals := make(map[string]any, len(v.RotatingVersion.Values))
			for k, v := range v.RotatingVersion.Values {
				vals[k] = v
			}
			secrets[v.Name] = vals
		case HVSSecretTypeDynamic:
			if v.DynamicInstance == nil {
				return nil, fmt.Errorf("dynamic secret %s has no DynamicInstance", v.Name)
			}
			// Since dynamic secrets have multiple values, prefix each key with
			// the secret name to avoid collisions.
			for dynamicKey, dynamicValue := range v.DynamicInstance.Values {
				prefixedKey := fmt.Sprintf("%s_%s", v.Name, dynamicKey)
				secrets[prefixedKey] = dynamicValue
			}

			vals := make(map[string]any, len(v.DynamicInstance.Values))
			for k, v := range v.DynamicInstance.Values {
				vals[k] = v
			}
			secrets[v.Name] = vals
		default:
			continue
		}

		if hasTemplates {
			// we only need the Secret's metadata if we have templates to render.
			m, err := s.makeHVSMetadata(v)
			if err != nil {
				return nil, err
			}

			// maps secret name to its secret metadata
			metadata[v.Name] = m
		}
	}

	if hasTemplates {
		data, err = renderTemplates(opt, NewSecretInput(secrets, metadata, opt.Annotations, opt.Labels))
		if err != nil {
			return nil, err
		}
	}

	return makeK8sData(secrets, data, raw, opt)
}

func (s *SecretDataBuilder) makeHVSMetadata(v *models.Secrets20231128OpenSecret) (map[string]any, error) {
	b, err := v.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// unmarshal to non-open secret, which should/must not contain any
	// secret/confidential data.
	//
	// Note: In API 2023-11-28, this conversion will lose the CreatedByID
	// field from OpenSecret{}, since it doesn't correspond to CreatedBy in
	// Secret{}
	// https://github.com/hashicorp/hcp-sdk-go/blob/v0.106.0/clients/cloud-vault-secrets/preview/2023-11-28/models/secrets20231128_open_secret.go#L27
	// https://github.com/hashicorp/hcp-sdk-go/blob/v0.106.0/clients/cloud-vault-secrets/preview/2023-11-28/models/secrets20231128_secret.go#L27
	var ss models.Secrets20231128Secret
	if err := json.Unmarshal(b, &ss); err != nil {
		return nil, err
	}

	if v.Type == HVSSecretTypeDynamic {
		// open dynamic secrets do not share the same fields as the non-open secrets, so
		// we need to convert them here.
		if ss.DynamicConfig == nil {
			ss.DynamicConfig = &models.Secrets20231128SecretDynamicConfig{}
		}
		ss.DynamicConfig.TTL = v.DynamicInstance.TTL
	}

	sv, err := ss.MarshalBinary()
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(sv, &m); err != nil {
		return nil, err
	}

	return m, nil
}

// makeK8sData returns the filtered data for the destination K8s Secret. It
// always adds the _raw data bytes, which is typically a secret source's entire
// response. Any extraData will always be included in the result data. Returns a
// SecretDataErrorContainsRaw error if either secretData or extraData contain
// SecretDataKeyRaw .
func makeK8sData[V any](secretData map[string]V, extraData map[string][]byte,
	raw []byte, opt *SecretTransformationOption,
) (map[string][]byte, error) {
	data := make(map[string][]byte)
	if !opt.ExcludeRaw {
		if _, ok := secretData[SecretDataKeyRaw]; ok {
			return nil, SecretDataErrorContainsRaw
		}

		if _, ok := extraData[SecretDataKeyRaw]; ok {
			return nil, SecretDataErrorContainsRaw
		}

		data[SecretDataKeyRaw] = raw
	}
	for k, v := range extraData {
		data[k] = v
	}

	filtered, err := filterData(opt, secretData)
	if err != nil {
		return nil, err
	}

	// include the filtered fields that are not already in data
	for k, v := range filtered {
		if _, ok := data[k]; !ok {
			bv, err := marshalJSON(v)
			if err != nil {
				return nil, err
			}
			data[k] = bv
		}
	}

	return data, nil
}

func NewSecretsDataBuilder() *SecretDataBuilder {
	return &SecretDataBuilder{}
}

// MakeHVSShadowSecretData converts a list of HVS OpenSecrets to k8s secret data.
func MakeHVSShadowSecretData(secrets []*models.Secrets20231128OpenSecret) (map[string][]byte, error) {
	data := make(map[string][]byte)
	for _, v := range secrets {
		if v.DynamicInstance == nil {
			continue
		}
		secretData, err := marshalJSON(v)
		if err != nil {
			return nil, err
		}
		data[v.Name] = secretData
	}

	return data, nil
}

// FromHVSShadowSecret converts a k8s secret data entry to an HVS OpenSecret.
func FromHVSShadowSecret(data []byte) (*models.Secrets20231128OpenSecret, error) {
	var secret models.Secrets20231128OpenSecret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, err
	}

	return &secret, nil
}

// HashString returns the first eight + last four characters of the sha256 sum
// of the input string.
func HashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return strings.ToLower(fmt.Sprintf("%x%x", sum[0:7], sum[len(sum)-4:]))
}
