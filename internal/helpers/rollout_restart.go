// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"errors"
	"fmt"
	"time"

	argorolloutsv1alpha1 "github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

// AnnotationRestartedAt is updated to trigger a rollout-restart
const AnnotationRestartedAt = "vso.secrets.hashicorp.com/restartedAt"

// HandleRolloutRestarts for all v1beta1.RolloutRestartTarget(s) configured for obj.
// Supported objs are: v1beta1.VaultDynamicSecret, v1beta1.VaultStaticSecret, v1beta1.VaultPKISecret
// Please note the following:
// - a rollout-restart will be triggered for each configured v1beta1.RolloutRestartTarget
// - the rollout-restart action has no support for roll-back
// - does not wait for the action to complete
//
// Returns all errors encountered.
func HandleRolloutRestarts(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, recorder record.EventRecorder) error {
	logger := log.FromContext(ctx)

	var targets []v1beta1.RolloutRestartTarget
	switch t := obj.(type) {
	case *v1beta1.VaultDynamicSecret:
		targets = t.Spec.RolloutRestartTargets
	case *v1beta1.VaultStaticSecret:
		targets = t.Spec.RolloutRestartTargets
	case *v1beta1.VaultPKISecret:
		targets = t.Spec.RolloutRestartTargets
	case *v1beta1.HCPVaultSecretsApp:
		targets = t.Spec.RolloutRestartTargets
	default:
		err := fmt.Errorf("unsupported Object type %T", t)
		recorder.Eventf(obj, corev1.EventTypeWarning, consts.ReasonRolloutRestartUnsupported,
			"Rollout restart impossible (please report this bug): err=%s", err)
		return err
	}

	if len(targets) == 0 {
		return nil
	}

	var errs error
	for _, target := range targets {
		if err := RolloutRestart(ctx, obj.GetNamespace(), target, client); err != nil {
			errs = errors.Join(err)
			recorder.Eventf(obj, corev1.EventTypeWarning, consts.ReasonRolloutRestartFailed,
				"Rollout restart failed for target %#v: err=%s", target, err)
		} else {
			recorder.Eventf(obj, corev1.EventTypeNormal, consts.ReasonRolloutRestartTriggered,
				"Rollout restart triggered for %v", target)
		}
	}

	if errs != nil {
		logger.Error(errs, "Rollout restart failed", "targets", targets)
	} else {
		logger.V(consts.LogLevelDebug).Info("Rollout restart succeeded", "total", len(targets))
	}

	return errs
}

// RolloutRestart patches the target in namespace for rollout-restart.
// Supported target Kinds are: DaemonSet, Deployment, StatefulSet
func RolloutRestart(ctx context.Context, namespace string, target v1beta1.RolloutRestartTarget, client ctrlclient.Client) error {
	if namespace == "" {
		return fmt.Errorf("namespace cannot be empty")
	}

	objectMeta := metav1.ObjectMeta{
		Namespace: namespace,
		Name:      target.Name,
	}

	var obj ctrlclient.Object
	switch target.Kind {
	case "DaemonSet":
		obj = &appsv1.DaemonSet{
			ObjectMeta: objectMeta,
		}
	case "Deployment":
		obj = &appsv1.Deployment{
			ObjectMeta: objectMeta,
		}
	case "StatefulSet":
		obj = &appsv1.StatefulSet{
			ObjectMeta: objectMeta,
		}
	case "argo.Rollout":
		obj = &argorolloutsv1alpha1.Rollout{
			ObjectMeta: objectMeta,
		}
	default:
		return fmt.Errorf("unsupported Kind %q for %T", target.Kind, target)
	}

	return patchForRolloutRestart(ctx, obj, client)
}

func patchForRolloutRestart(ctx context.Context, obj ctrlclient.Object, client ctrlclient.Client) error {
	objKey := ctrlclient.ObjectKeyFromObject(obj)
	if err := client.Get(ctx, objKey, obj); err != nil {
		return fmt.Errorf("failed to Get object for objKey %s, err=%w", objKey, err)
	}

	switch t := obj.(type) {
	case *appsv1.Deployment:
		if t.Spec.Paused {
			return fmt.Errorf("deployment %s is paused, cannot restart it", obj)
		}
		patch := ctrlclient.StrategicMergeFrom(t.DeepCopy())
		if t.Spec.Template.ObjectMeta.Annotations == nil {
			t.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
		}
		t.Spec.Template.ObjectMeta.Annotations[AnnotationRestartedAt] = time.Now().Format(time.RFC3339)
		return client.Patch(ctx, t, patch)
	case *appsv1.StatefulSet:
		patch := ctrlclient.StrategicMergeFrom(t.DeepCopy())
		if t.Spec.Template.ObjectMeta.Annotations == nil {
			t.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
		}
		t.Spec.Template.ObjectMeta.Annotations[AnnotationRestartedAt] = time.Now().Format(time.RFC3339)
		return client.Patch(ctx, t, patch)
	case *appsv1.DaemonSet:
		patch := ctrlclient.StrategicMergeFrom(t.DeepCopy())
		if t.Spec.Template.ObjectMeta.Annotations == nil {
			t.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
		}
		t.Spec.Template.ObjectMeta.Annotations[AnnotationRestartedAt] = time.Now().Format(time.RFC3339)
		return client.Patch(ctx, t, patch)
	case *argorolloutsv1alpha1.Rollout:
		// use MergeFrom() since it supports CRDs whereas StrategicMergeFrom() does not.
		patch := ctrlclient.MergeFrom(t.DeepCopy())
		t.Spec.RestartAt = &metav1.Time{Time: time.Now()}
		return client.Patch(ctx, t, patch)
	default:
		return fmt.Errorf("unsupported type %T for rollout-restart patching", t)
	}
}
