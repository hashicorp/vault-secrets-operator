// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

// secretKeyRefSeparator separates the components of a VaultStaticSecret
// spec.data reference.
const secretKeyRefSeparator = "#"

// secretKeyRef is a parsed VaultStaticSecret spec.data reference of the form
// SECRET_PATH#KEY[#VERSION].
type secretKeyRef struct {
	// Path of the Vault secret, relative to the resource's mount.
	Path string
	// Key within the Vault secret.
	Key string
	// Version of the Vault secret to read. Only valid for kv-v2. Zero means
	// the latest version, matching the semantics of spec.version.
	Version int
}

// String returns the canonical reference string for r.
func (r secretKeyRef) String() string {
	s := r.Path + secretKeyRefSeparator + r.Key
	if r.Version > 0 {
		s += secretKeyRefSeparator + strconv.Itoa(r.Version)
	}
	return s
}

// parseSecretKeyRef parses a VaultStaticSecret spec.data value of the form
// SECRET_PATH#KEY[#VERSION]. The path may contain "/" but neither the path nor
// the key may contain the "#" separator.
func parseSecretKeyRef(ref string) (secretKeyRef, error) {
	var result secretKeyRef

	parts := strings.Split(ref, secretKeyRefSeparator)
	if len(parts) < 2 || len(parts) > 3 {
		return result, fmt.Errorf(
			"invalid secret reference %q, want SECRET_PATH%sKEY[%sVERSION]",
			ref, secretKeyRefSeparator, secretKeyRefSeparator)
	}

	// Trim the leading "/" so that "/foo/bar#key" and "foo/bar#key" resolve to
	// the same Vault path, and so that distinct spellings of the same path are
	// not read twice.
	result.Path = strings.TrimPrefix(strings.TrimSpace(parts[0]), "/")
	result.Key = strings.TrimSpace(parts[1])

	if result.Path == "" {
		return secretKeyRef{}, fmt.Errorf("invalid secret reference %q, path is empty", ref)
	}
	if result.Key == "" {
		return secretKeyRef{}, fmt.Errorf("invalid secret reference %q, key is empty", ref)
	}

	if len(parts) == 3 {
		v := strings.TrimSpace(parts[2])
		version, err := strconv.Atoi(v)
		if err != nil {
			return secretKeyRef{}, fmt.Errorf(
				"invalid secret reference %q, version %q is not an integer", ref, v)
		}
		if version < 0 {
			return secretKeyRef{}, fmt.Errorf(
				"invalid secret reference %q, version %d is negative", ref, version)
		}
		result.Version = version
	}

	return result, nil
}

// parseSecretKeyRefs parses every entry of spec.data, returning the parsed
// references keyed by their destination Secret key. Destination keys are
// validated against the referenced Vault secret type: pinning a version is
// only supported for kv-v2.
func parseSecretKeyRefs(spec secretsv1beta1.VaultStaticSecretSpec) (map[string]secretKeyRef, error) {
	if len(spec.Data) == 0 {
		return nil, nil
	}

	refs := make(map[string]secretKeyRef, len(spec.Data))
	for _, destKey := range sortedKeys(spec.Data) {
		ref, err := parseSecretKeyRef(spec.Data[destKey])
		if err != nil {
			return nil, fmt.Errorf(".spec.data[%q]: %w", destKey, err)
		}
		if ref.Version > 0 && spec.Type != consts.KVSecretTypeV2 {
			return nil, fmt.Errorf(
				".spec.data[%q]: version is only supported for secret type %s, got %q",
				destKey, consts.KVSecretTypeV2, spec.Type)
		}
		refs[destKey] = ref
	}

	return refs, nil
}

// validateVaultStaticSecretSpec validates the Vault source configuration of
// spec and returns its parsed spec.data references.
//
// The CRD carries an equivalent "one of path or data" CEL rule, but
// x-kubernetes-validations is only evaluated on Kubernetes 1.25 and later and
// the chart supports 1.21+, so the constraint is enforced here as well.
func validateVaultStaticSecretSpec(spec secretsv1beta1.VaultStaticSecretSpec) (map[string]secretKeyRef, error) {
	switch spec.Type {
	case consts.KVSecretTypeV1, consts.KVSecretTypeV2:
	default:
		return nil, fmt.Errorf("unsupported secret type %q", spec.Type)
	}

	if spec.Path == "" && len(spec.Data) == 0 {
		return nil, errors.New("one of .spec.path or .spec.data must be set")
	}

	return parseSecretKeyRefs(spec)
}

// kvReadKey identifies a single Vault read, so that several spec.data entries
// referencing the same path and version only result in one Vault request.
type kvReadKey struct {
	path    string
	version int
}

// readVaultStaticSecretData resolves the Vault data for o.
//
// It returns the secret data that should be synced to the destination Secret,
// along with the raw Vault response data used for the destination's `_raw` key
// and as the template input. When spec.data is set, the returned raw data
// carries the aggregated secret data rather than the response of a single
// Vault read; for kv-v2 the metadata of the spec.path read, if any, is
// preserved so that templates can continue to reference it.
func readVaultStaticSecretData(ctx context.Context, c vault.Client,
	o *secretsv1beta1.VaultStaticSecret, headers http.Header,
) (map[string]any, map[string]any, error) {
	spec := o.Spec

	refs, err := validateVaultStaticSecretSpec(spec)
	if err != nil {
		return nil, nil, err
	}

	data := make(map[string]any)
	var raw map[string]any

	if spec.Path != "" {
		kvReq, err := newKVRequest(spec, headers)
		if err != nil {
			return nil, nil, err
		}

		resp, err := c.Read(ctx, kvReq)
		if err != nil {
			return nil, nil, err
		}

		for k, v := range resp.Data() {
			data[k] = v
		}
		raw = resp.Secret().Data
	}

	if len(refs) == 0 {
		// Preserve the pre-aggregation behaviour exactly for the common
		// single-path case.
		return data, raw, nil
	}

	// Read each distinct (path, version) at most once, then overlay the
	// referenced keys on top of the data read from spec.path.
	cache := make(map[kvReadKey]map[string]any)
	for _, destKey := range sortedKeys(refs) {
		ref := refs[destKey]
		rk := kvReadKey{path: ref.Path, version: ref.Version}

		srcData, ok := cache[rk]
		if !ok {
			req, err := newKVRequestForPath(spec.Type, spec.Mount, ref.Path, ref.Version, headers)
			if err != nil {
				return nil, nil, err
			}

			resp, err := c.Read(ctx, req)
			if err != nil {
				return nil, nil, fmt.Errorf(
					"failed to read Vault secret %q referenced by .spec.data[%q]: %w",
					ref.String(), destKey, err)
			}

			srcData = resp.Data()
			if srcData == nil {
				srcData = map[string]any{}
			}
			cache[rk] = srcData
		}

		v, ok := srcData[ref.Key]
		if !ok {
			return nil, nil, fmt.Errorf(
				"key %q not found in Vault secret %q referenced by .spec.data[%q]",
				ref.Key, ref.Path, destKey)
		}

		data[destKey] = v
	}

	return data, aggregatedRawData(spec.Type, raw, data), nil
}

// aggregatedRawData builds the raw Vault data for an aggregated secret. The
// shape of the result matches the shape of a Vault read response for
// secretType, so that the destination's `_raw` key and the template input stay
// consistent with the non-aggregated case. Any non-payload fields of baseRaw
// (notably kv-v2 `metadata`) are carried over.
func aggregatedRawData(secretType string, baseRaw, data map[string]any) map[string]any {
	if secretType != consts.KVSecretTypeV2 {
		return data
	}

	raw := make(map[string]any, len(baseRaw)+1)
	for k, v := range baseRaw {
		raw[k] = v
	}
	raw["data"] = data

	return raw
}

// vaultEventPaths returns the distinct Vault event paths that o depends on, in
// stable order. Unparsable spec.data entries are skipped: reconciliation
// already fails on those, and there is no path to subscribe to.
func vaultEventPaths(o *secretsv1beta1.VaultStaticSecret) []string {
	seen := make(map[string]struct{})
	var paths []string

	add := func(p string) {
		if p == "" {
			return
		}
		eventPath := buildVaultEventPath(o.Spec.Type, o.Spec.Mount, p)
		if _, ok := seen[eventPath]; ok {
			return
		}
		seen[eventPath] = struct{}{}
		paths = append(paths, eventPath)
	}

	add(o.Spec.Path)
	for _, destKey := range sortedKeys(o.Spec.Data) {
		ref, err := parseSecretKeyRef(o.Spec.Data[destKey])
		if err != nil {
			continue
		}
		add(ref.Path)
	}

	sort.Strings(paths)

	return paths
}

// sortedKeys returns the keys of m in ascending order, so that Vault reads and
// any resulting errors are deterministic.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}
