/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"

	"github.com/hashicorp/vault/api"
)

// VaultSecretReconciler reconciles a VaultSecret object
type VaultSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultsecrets/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the VaultSecret object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *VaultSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var s secretsv1alpha1.VaultSecret
	if err := r.Client.Get(ctx, req.NamespacedName, &s); err != nil {
		if apierrors.IsNotFound(err) {
			// TODO: delete the secret?
			return ctrl.Result{}, nil
		}

		l.Error(err, "error getting resource from k8s", "secret", s)
		return ctrl.Result{}, err
	}

	spec := s.Spec

	if spec.Type != "kvv2" {
		err := fmt.Errorf("unsupported secret type %q", spec.Type)
		l.Error(err, "")
		return ctrl.Result{}, err
	}

	sec1 := &corev1.Secret{}
	if err := r.Client.Get(ctx,
		types.NamespacedName{
			Namespace: s.Namespace,
			Name:      spec.Dest,
		},
		sec1,
	); err != nil {
		return ctrl.Result{}, err
	}

	l.Info(fmt.Sprintf("%#v", sec1))

	c, err := r.getVaultClient(ctx, spec)
	if err != nil {
		return ctrl.Result{}, err
	}
	if _, err = c.Sys().SealStatus(); err != nil {
		l.Error(err, "error getting Vault status")
		return ctrl.Result{}, err
	}

	//status, _ := c.Sys().SealStatus()
	//l.Info(fmt.Sprintf("Vault seal status %#v", status))

	var refAfter time.Duration
	if spec.RefreshAfter != "" {
		d, err := time.ParseDuration(spec.RefreshAfter)
		if err != nil {
			l.Error(err, "failed to parse spec.RefreshAfter")
			return ctrl.Result{}, err
		}
		refAfter = d
	}

	path := r.getKVV2Path(spec.Mount, spec.Name)
	l.Info(fmt.Sprintf("Read it :) %q", path), "secret", s)
	resp, err := c.Logical().Read(path)
	if err != nil {
		l.Error(err, "error reading secret %q")
		return ctrl.Result{
			RequeueAfter: refAfter,
		}, err
	}

	if resp == nil {
		l.Error(err, "empty Vault secret", "path", path)
		return ctrl.Result{
			RequeueAfter: refAfter,
		}, err
	}

	l.Info(fmt.Sprintf("Resp %#v", resp))

	b, err := json.Marshal(resp.Data)
	sec1.Data = map[string][]byte{
		"data": b,
	}
	if err := r.Client.Update(ctx, sec1); err != nil {
		l.Error(err, "error reading secret %q")
		return ctrl.Result{}, err
	}

	// TODO:
	// - store KV in a k8s secret
	// - support deletion
	// - support app webhook registration for rotation signalling
	// - add support for db creds, to demo dynamic credential rotation
	// - prepare single slide for Weds.

	// set ctrl.Result.Requeue to true with RequeueAfter being the credential (expiry TTL - some offset)
	return ctrl.Result{
		RequeueAfter: refAfter,
	}, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultSecret{}).
		Complete(r)
}

func (r *VaultSecretReconciler) getVaultClient(ctx context.Context, spec secretsv1alpha1.VaultSecretSpec) (*api.Client,
	error) {
	l := log.FromContext(ctx)
	config := api.DefaultConfig()
	// TODO: get this from config, probably from env var VAULT_ADDR=http://vault.demo.svc.cluster.local:8200
	config.Address = "http://vault.demo.svc.cluster.local:8200"
	c, err := api.NewClient(config)
	if err != nil {
		l.Error(err, "error setting up Vault API client")
		return nil, err
	}
	//TODO: get this from the service account, setup k8s-auth
	c.SetToken("root")

	l.Info(fmt.Sprintf("Getting Vault client, ns=%q", spec.Namespace))
	if spec.Namespace != "" {
		c.SetNamespace(spec.Namespace)
	}
	return c, nil
}

func (r *VaultSecretReconciler) getKVV2Path(mount, name string) string {
	return joinPath(mount, "data", name)
}

func joinPath(parts ...string) string {
	return strings.Join(parts, "/")
}
