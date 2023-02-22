// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/controllers"
	vclient "github.com/hashicorp/vault-secrets-operator/internal/vault"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(secretsv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var lruClientCacheSize int
	var lruObjectKeyCacheSize int
	flag.IntVar(&lruClientCacheSize, "client-lru-cache-size", 10000, "Size of the in-memory LRU client cache.")
	flag.IntVar(&lruObjectKeyCacheSize, "object-key-lru-cache-size", 10000, "Size of the in-memory LRU object-key cache.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	persistenceModelNone := "none"
	persistenceModelDirect := "direct"
	persistenceModelEncrypted := "direct-encrypted"
	defaultPersistenceModel := persistenceModelNone
	var clientCachePersistenceModel string
	flag.StringVar(&clientCachePersistenceModel, "client-cache-persistence-model", defaultPersistenceModel,
		fmt.Sprintf(
			"The type of client cache persistence model that should be employed."+
				"choices=%v", []string{persistenceModelDirect, persistenceModelEncrypted, persistenceModelNone}))
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	vaultClientCacheOptions := &controllers.VaultClientCacheOptions{}
	switch clientCachePersistenceModel {
	case persistenceModelDirect:
		vaultClientCacheOptions.Persist = true
	case persistenceModelEncrypted:
		vaultClientCacheOptions.Persist = true
		vaultClientCacheOptions.RequireEncryption = true
	case persistenceModelNone:
		vaultClientCacheOptions.Persist = false
		vaultClientCacheOptions.RequireEncryption = false
	default:
		setupLog.Error(errors.New("unsupported persistence model"),
			fmt.Sprintf("%q is not a valid cache pesistence configuration model", clientCachePersistenceModel))
		os.Exit(1)
	}

	setupLog.Info("Client cache persistence", "model", clientCachePersistenceModel)

	clientCache, err := vclient.NewClientCache(lruClientCacheSize)
	if err != nil {
		setupLog.Error(err, "Unable to create Vault ClientCache")
		os.Exit(1)
	}

	objectKeyCache, err := vclient.NewObjectKeyCache(lruObjectKeyCacheSize)
	if err != nil {
		setupLog.Error(err, "Unable to create Vault ObjectKeyCache")
		os.Exit(1)
	}

	clientCacheManager, err := vclient.NewClientCacheManager(clientCache, objectKeyCache)
	if err != nil {
		setupLog.Error(err, "Unable to create Vault ClientCacheManager")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "b0d477c0.hashicorp.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Unable to start manager")
		os.Exit(1)
	}

	if err = (&controllers.VaultStaticSecretReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Recorder:           mgr.GetEventRecorderFor("VaultStaticSecret"),
		ClientCacheManager: clientCacheManager,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultStaticSecret")
		os.Exit(1)
	}
	if err = (&controllers.VaultPKISecretReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		ClientCacheManager: clientCacheManager,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultPKISecret")
		os.Exit(1)
	}
	if err = (&controllers.VaultAuthReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("VaultAuth"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultAuth")
		os.Exit(1)
	}
	if err = (&controllers.VaultConnectionReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("VaultConnection"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultConnection")
		os.Exit(1)
	}
	if err = (&controllers.VaultDynamicSecretReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Recorder:           mgr.GetEventRecorderFor("VaultDynamicSecret"),
		ClientCacheManager: clientCacheManager,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultDynamicSecret")
		os.Exit(1)
	}
	if err = (&controllers.VaultClientCacheReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Recorder:    mgr.GetEventRecorderFor("VaultClientCache"),
		Options:     vaultClientCacheOptions,
		ClientCache: clientCache,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultClientCache")
		os.Exit(1)
	}
	if err = (&controllers.VaultTransitReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("VaultTransit"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultTransit")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up ready check")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	setupLog.Info("Starting manager",
		"clientCachePersistenceModel", clientCachePersistenceModel,
		"clientCacheSize", lruClientCacheSize,
		"objectKeyCacheSize", lruObjectKeyCacheSize,
	)
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
