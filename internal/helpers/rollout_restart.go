// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

func RolloutRestart(ctx context.Context, s v1.Object, target v1alpha1.RolloutRestartTarget, ctrlClient client.Client) error {
	var obj client.Object
	switch target.Kind {
	case "DaemonSet":
		obj = &appsv1.DaemonSet{
			ObjectMeta: v1.ObjectMeta{
				Namespace: s.GetNamespace(),
				Name:      s.GetName(),
			},
		}
	case "Deployment":
		obj = &appsv1.Deployment{
			ObjectMeta: v1.ObjectMeta{
				Namespace: s.GetNamespace(),
				Name:      s.GetName(),
			},
		}
	case "StatefulSet":
		obj = &appsv1.StatefulSet{
			ObjectMeta: v1.ObjectMeta{
				Namespace: s.GetNamespace(),
				Name:      s.GetName(),
			},
		}
	default:
		return fmt.Errorf("unsupported Kind %s for %T", target.Kind, target)
	}

	return patchForRolloutRestart(ctx, obj, ctrlClient)
}

func patchForRolloutRestart(ctx context.Context, obj client.Object, ctrlClient client.Client) error {
	if err := ctrlClient.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		} else {
			return err
		}
	}

	switch t := obj.(type) {
	case *appsv1.Deployment:
		if t.Spec.Paused {
			return fmt.Errorf("deployment %s is restart, cannot restart it", obj)
		}
		patch := client.StrategicMergeFrom(t.DeepCopy())
		if t.Spec.Template.ObjectMeta.Annotations == nil {
			t.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
		}
		t.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
		return ctrlClient.Patch(ctx, t, patch)
	case *appsv1.StatefulSet:
		patch := client.StrategicMergeFrom(t.DeepCopy())
		if t.Spec.Template.ObjectMeta.Annotations == nil {
			t.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
		}
		t.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
		return ctrlClient.Patch(ctx, t, patch)
	case *appsv1.DaemonSet:
		patch := client.StrategicMergeFrom(t.DeepCopy())
		if t.Spec.Template.ObjectMeta.Annotations == nil {
			t.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
		}
		t.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
		return ctrlClient.Patch(ctx, t, patch)
	default:
		return fmt.Errorf("unsupported type %T for rollout-restart patching", t)
	}
}
