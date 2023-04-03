// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/controllers"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
	vclient "github.com/hashicorp/vault-secrets-operator/internal/vault"
	"github.com/hashicorp/vault-secrets-operator/internal/version"
	//+kubebuilder:scaffold:imports
)

var (
	scheme              = runtime.NewScheme()
	setupLog            = ctrl.Log.WithName("setup")
	finalizerCleanupLog = ctrl.Log.WithName("cleanup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(secretsv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	persistenceModelNone := "none"
	persistenceModelDirectUnencrypted := "direct-unencrypted"
	persistenceModelDirectEncrypted := "direct-encrypted"
	defaultPersistenceModel := persistenceModelNone
	vdsOptions := controller.Options{}
	cfc := vclient.DefaultCachingClientFactoryConfig()

	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var clientCachePersistenceModel string
	var printVersion bool
	var finalizerCleanup bool
	flag.BoolVar(&printVersion, "version", false, "Print the operator version information")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.IntVar(&cfc.ClientCacheSize, "client-cache-size", cfc.ClientCacheSize,
		"Size of the in-memory LRU client cache.")
	flag.StringVar(&clientCachePersistenceModel, "client-cache-persistence-model", defaultPersistenceModel,
		fmt.Sprintf(
			"The type of client cache persistence model that should be employed."+
				"choices=%v", []string{persistenceModelDirectUnencrypted, persistenceModelDirectEncrypted, persistenceModelNone}))
	flag.IntVar(&vdsOptions.MaxConcurrentReconciles, "max-concurrent-reconciles-vds", 100,
		"Maximum number of concurrent reconciles for the VaultDynamicSecrets controller.")
	flag.BoolVar(&finalizerCleanup, "finalizer-cleanup", false, "Remove finalizers from all CRs in preparation for shutdown.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	// versionInfo is used when setting up the buildInfo metric below
	versionInfo := version.Version()
	if printVersion {
		if _, err := os.Stdout.WriteString(fmt.Sprintf("%#v\n", versionInfo)); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	config := ctrl.GetConfigOrDie()

	// This flag is passed by the pre-delete hook on helm uninstall.
	if finalizerCleanup {
		finalizerCleanupLog.Info("commencing cleanup of finalizers")
		var finalizerCleanupClient client.Client
		finalizerCleanupClient, err := client.New(config, client.Options{
			Scheme: scheme,
		})

		d := time.Now().Add(time.Second * 60)
		shutdownCtx, cancel := context.WithDeadline(context.Background(), d)
		// Even though ctx will be expired, it is good practice to call its
		// cancellation function in any case. Failure to do so may keep the
		// context and its parent alive longer than necessary.
		defer cancel()

		finalizerCleanupLog.Info("deleting finalizers")
		if err = controllers.RemoveAllFinalizers(shutdownCtx, finalizerCleanupClient, finalizerCleanupLog); err != nil {
			finalizerCleanupLog.Error(err, "unable to remove finalizers")
			os.Exit(1)
		}
		return
	}

	mgr, err := ctrl.NewManager(config, ctrl.Options{
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
		//LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Unable to start manager")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	collectMetrics := metricsAddr != ""
	if collectMetrics {
		cfc.MetricsRegistry.MustRegister(
			metrics.NewBuildInfoGauge(versionInfo),
		)
		vclient.MustRegisterClientMetrics(cfc.MetricsRegistry)
	}
	var clientFactory vclient.CachingClientFactory
	{
		switch clientCachePersistenceModel {
		case persistenceModelDirectUnencrypted:
			cfc.Persist = true
		case persistenceModelDirectEncrypted:
			cfc.Persist = true
			cfc.StorageConfig.EnforceEncryption = true
		case persistenceModelNone:
			cfc.Persist = false
		default:
			setupLog.Error(errors.New("invalid option"),
				fmt.Sprintf("Invalid cache pesistence model %q", clientCachePersistenceModel))
			os.Exit(1)
		}

		defaultClient, err := client.New(config, client.Options{
			Scheme: mgr.GetScheme(),
		})
		if err != nil {
			setupLog.Error(err, "Failed to instantiate a default Client")
			os.Exit(1)
		}

		cfc.CollectClientCacheMetrics = collectMetrics
		cfc.Recorder = mgr.GetEventRecorderFor("vaultClientFactory")
		clientFactory, err = vclient.InitCachingClientFactory(ctx, defaultClient, cfc)
		if err != nil {
			setupLog.Error(err, "Failed to setup the Vault ClientFactory")
			os.Exit(1)
		}
	}

	if err = (&controllers.VaultStaticSecretReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Recorder:        mgr.GetEventRecorderFor("VaultStaticSecret"),
		HMACFunc:        vclient.NewHMACFromSecretFunc(cfc.StorageConfig.HMACSecretObjKey),
		ValidateMACFunc: vclient.NewMACValidateFromSecretFunc(cfc.StorageConfig.HMACSecretObjKey),
		ClientFactory:   clientFactory,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultStaticSecret")
		os.Exit(1)
	}
	if err = (&controllers.VaultPKISecretReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		ClientFactory: clientFactory,
		Recorder:      mgr.GetEventRecorderFor("VaultPKISecret"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultPKISecret")
		os.Exit(1)
	}
	if err = (&controllers.VaultAuthReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Recorder:      mgr.GetEventRecorderFor("VaultAuth"),
		ClientFactory: clientFactory,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultAuth")
		os.Exit(1)
	}
	if err = (&controllers.VaultConnectionReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Recorder:      mgr.GetEventRecorderFor("VaultConnection"),
		ClientFactory: clientFactory,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultConnection")
		os.Exit(1)
	}
	if err = (&controllers.VaultDynamicSecretReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Recorder:      mgr.GetEventRecorderFor("VaultDynamicSecret"),
		ClientFactory: clientFactory,
	}).SetupWithManager(mgr, vdsOptions); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultDynamicSecret")
		os.Exit(1)
	}
	if err = (&controllers.VaultKubernetesAuthBackendReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Recorder:      mgr.GetEventRecorderFor("VaultKubernetesAuthBackend"),
		ClientFactory: clientFactory,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultKubernetesAuthBackend")
		os.Exit(1)
	}
	if err = (&controllers.VaultAuthBackendReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Recorder:      mgr.GetEventRecorderFor("VaultAuthBackend"),
		ClientFactory: clientFactory,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultAuthBackend")
		os.Exit(1)
	}
	if err = (&controllers.VaultKubernetesAuthBackendRoleReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Recorder:      mgr.GetEventRecorderFor("VaultAuthBackend"),
		ClientFactory: clientFactory,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultKubernetesAuthBackendRole")
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

	setupLog.Info("Starting manager",
		"clientCachePersistenceModel", clientCachePersistenceModel,
		"clientCacheSize", cfc.ClientCacheSize,
	)

	mgr.GetCache()
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
