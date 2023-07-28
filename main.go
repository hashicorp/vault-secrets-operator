// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
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

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/controllers"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
	vclient "github.com/hashicorp/vault-secrets-operator/internal/vault"
	"github.com/hashicorp/vault-secrets-operator/internal/version"
	//+kubebuilder:scaffold:imports
)

var (
	scheme     = runtime.NewScheme()
	setupLog   = ctrl.Log.WithName("setup")
	cleanupLog = ctrl.Log.WithName("cleanup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(secretsv1beta1.AddToScheme(scheme))
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
	var outputFormat string
	var preDeleteHook bool
	var preDeleteHookTimeoutSeconds int
	var revokeVaultTokensOnUninstall bool
	var pruneVaultTokensOnUninstall bool

	// command-line args and flags
	flag.BoolVar(&printVersion, "version", false, "Print the operator version information")
	flag.StringVar(&outputFormat, "output", "", "Output format for the operator version information (yaml or json)")
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
	flag.BoolVar(&preDeleteHook, "pre-delete-hook", false, "Run as helm pre-delete hook")
	flag.BoolVar(&revokeVaultTokensOnUninstall, "revoke-vault-tokens-on-uninstall", false,
		"Revoke all cached Vault client tokens on Helm uninstall.")
	flag.BoolVar(&pruneVaultTokensOnUninstall, "prune-vault-tokens-on-uninstall", false,
		"Prune all Vault client tokens in storage on Helm uninstall.")
	flag.IntVar(&preDeleteHookTimeoutSeconds, "pre-delete-hook-timeout-seconds", 120,
		"Pre-delete hook timeout in seconds")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	preDeleteDeadline := time.Now().Add(time.Second * time.Duration(preDeleteHookTimeoutSeconds))

	// versionInfo is used when setting up the buildInfo metric below
	versionInfo := version.Version()
	if printVersion {
		outputString := ""
		switch outputFormat {
		case "":
			outputString = fmt.Sprintf("%#v\n", versionInfo)
		case "yaml":
			yamlBytes, err := yaml.Marshal(&versionInfo)
			if err != nil {
				os.Exit(1)
			}
			outputString = string(yamlBytes)
		case "json":
			jsonBytes, err := json.MarshalIndent(&versionInfo, "", "  ")
			if err != nil {
				os.Exit(1)
			}
			outputString = string(jsonBytes)
		default:
			if _, err := os.Stderr.WriteString("--output should be either 'yaml' or 'json'\n"); err != nil {
				os.Exit(1)
			}
			os.Exit(1)
		}
		if _, err := os.Stdout.WriteString(outputString); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	config := ctrl.GetConfigOrDie()

	defaultClient, err := client.NewWithWatch(config, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		setupLog.Error(err, "Failed to instantiate a default Client")
		os.Exit(1)
	}

	if preDeleteHook {
		cleanupLog.Info("commencing cleanup of finalizers")
		preDeleteDeadlineCtx, cancel := context.WithDeadline(context.Background(), preDeleteDeadline)
		// Even though ctx will be expired, it is good practice to call its
		// cancellation function in any case. Failure to do so may keep the
		// context and its parent alive longer than necessary.
		defer cancel()

		cleanupLog.Info("deleting finalizers")
		if err = controllers.RemoveAllFinalizers(preDeleteDeadlineCtx, defaultClient, cleanupLog); err != nil {
			cleanupLog.Error(err, "unable to remove finalizers")
			os.Exit(1)
		}

		if !revokeVaultTokensOnUninstall {
			return
		}
	}

	collectMetrics := metricsAddr != ""
	if collectMetrics {
		cfc.MetricsRegistry.MustRegister(
			metrics.NewBuildInfoGauge(versionInfo),
		)
		vclient.MustRegisterClientMetrics(cfc.MetricsRegistry)
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

		cfc.RevokeTokensOnUninstall = revokeVaultTokensOnUninstall
		cfc.StorageConfig.PruneVaultTokensOnUninstall = pruneVaultTokensOnUninstall
		cfc.CollectClientCacheMetrics = collectMetrics
		cfc.Recorder = mgr.GetEventRecorderFor("vaultClientFactory")
		clientFactory, err = vclient.InitCachingClientFactory(ctx, defaultClient, cfc)
		if err != nil {
			setupLog.Error(err, "Failed to setup the Vault ClientFactory")
			os.Exit(1)
		}
	}

	if revokeVaultTokensOnUninstall {
		var cancel context.CancelFunc
		if preDeleteHook {
			ctx, cancel = context.WithDeadline(context.Background(), preDeleteDeadline)
		}

		watcher, err := helpers.WatchManagerConfigMap(ctx, defaultClient)
		if err != nil {
			setupLog.Error(err, "Failed to setup the manager ConfigMap watcher")
			os.Exit(1)
		}

		if preDeleteHook {
			defer cancel()
			if err := helpers.SetConfigMapDeploymentShutdown(ctx, defaultClient); err != nil {
				cleanupLog.Error(err, "")
				return
			}
			helpers.WaitForInMemoryVaultTokensRevoked(ctx, cleanupLog, watcher)

			// Comment out when running test/integration/revocation_integration_test.go for error path testing.
			// In this case, we can ensure that all tokens cached in memory are revoked successfully.
			clientFactory.RevokeAllInStorage(ctx, defaultClient)
			return
		}

		revokeVaultTokensInMemory := func(ctx context.Context, m *v1.ConfigMap, c client.Client) error {
			if val, ok := m.Data[helpers.DeploymentShutdown]; ok && val == helpers.StringTrue {
				clientFactory.Disable()

				// Comment out when running test/integration/revocation_integration_test.go for error path testing.
				// In this case, we can ensure that all tokens in storage are revoked successfully.
				clientFactory.RevokeAllInMemory(ctx)
				if err := helpers.SetConfigMapInMemoryVaultTokensRevoked(ctx, c); err != nil {
					return fmt.Errorf("failed to set %s", helpers.DeploymentShutdown)
				}
			}
			return nil
		}

		go helpers.WaitForDeploymentShutdown(ctx, setupLog, watcher, defaultClient, revokeVaultTokensInMemory)
	}

	hmacValidator := vclient.NewHMACValidator(cfc.StorageConfig.HMACSecretObjKey)
	if err = (&controllers.VaultStaticSecretReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Recorder:      mgr.GetEventRecorderFor("VaultStaticSecret"),
		HMACValidator: hmacValidator,
		ClientFactory: clientFactory,
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
		HMACValidator: hmacValidator,
	}).SetupWithManager(mgr, vdsOptions); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultDynamicSecret")
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
