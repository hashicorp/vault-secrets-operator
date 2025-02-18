// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	argorolloutsv1alpha1 "github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"github.com/cenkalti/backoff/v4"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/yaml"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/helpers"
	"github.com/hashicorp/vault-secrets-operator/utils"
	vclient "github.com/hashicorp/vault-secrets-operator/vault"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/controllers"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
	"github.com/hashicorp/vault-secrets-operator/internal/options"
	"github.com/hashicorp/vault-secrets-operator/internal/version"
	// +kubebuilder:scaffold:imports
)

var (
	scheme     = runtime.NewScheme()
	setupLog   = ctrl.Log.WithName("setup")
	cleanupLog = ctrl.Log.WithName("cleanup")
)

const (
	// The default MaxConcurrentReconciles for the VDS controller.
	defaultVaultDynamicSecretsConcurrency = 100
	// The default MaxConcurrentReconciles for Syncable Secrets controllers.
	defaultSyncableSecretsConcurrency = 100
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(secretsv1beta1.AddToScheme(scheme))

	utilruntime.Must(argorolloutsv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// upgradeCRDs upgrades the CRDs in the cluster to the latest version.
func upgradeCRDs() error {
	root, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}

	var c client.Client
	config, err := ctrl.GetConfig()
	if err != nil {
		return err
	}

	s := runtime.NewScheme()
	if apiextensionsv1.AddToScheme(s) != nil {
		return err
	}

	c, err = client.New(config, client.Options{Scheme: s})
	if err != nil {
		return err
	}

	timeout := time.Second * 30
	if v := os.Getenv("VSO_UPGRADE_CRDS_TIMEOUT"); v != "" {
		if to, err := time.ParseDuration(v); err == nil {
			timeout = to
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return utils.UpgradeCRDs(ctx, c, filepath.Join(root, "crds"))
}

func main() {
	if filepath.Base(os.Args[0]) == "upgrade-crds" {
		// If the binary is named "upgrade-crds" then we are running in a job to upgrade
		// CRDs and exit. The docker image will contain a symlink to the binary with this
		// name. Following this pattern allows us to need only one image for executing
		// utility jobs like this.
		var exitCode int
		if err := upgradeCRDs(); err != nil {
			exitCode = 1
			os.Stderr.WriteString(fmt.Sprintf("failed to upgrade CRDs, err=%s\n", err))
		}
		os.Exit(exitCode)
	}

	persistenceModelNone := "none"
	persistenceModelDirectUnencrypted := "direct-unencrypted"
	persistenceModelDirectEncrypted := "direct-encrypted"
	defaultPersistenceModel := persistenceModelNone
	controllerOptions := controller.Options{}
	vdsOptions := controller.Options{}
	cfc := vclient.DefaultCachingClientFactoryConfig()
	startTime := time.Now()

	var vsoEnvOptions options.VSOEnvOptions
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var clientCachePersistenceModel string
	var printVersion bool
	var outputFormat string
	var uninstall bool
	var preDeleteHookTimeoutSeconds int
	var minRefreshAfterHVSA time.Duration
	var globalTransformationOpts string
	var globalVaultAuthOpts string
	var backoffInitialInterval time.Duration
	var backoffMaxInterval time.Duration
	var backoffRandomizationFactor float64
	var backoffMultiplier float64
	var backoffMaxElapsedTime time.Duration

	// command-line args and flags
	flag.BoolVar(&printVersion, "version", false, "Print the operator version information")
	flag.StringVar(&outputFormat, "output", "",
		"Output format for the operator version information (yaml or json). "+
			"Also set from environment variable VSO_OUTPUT_FORMAT.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.IntVar(&cfc.ClientCacheSize, "client-cache-size", cfc.ClientCacheSize,
		"Size of the in-memory LRU client cache. "+
			"Also set from environment variable VSO_CLIENT_CACHE_SIZE.")
	// update chart/values.yaml if changing the default value
	flag.IntVar(&cfc.ClientCacheNumLocks, "client-cache-num-locks", 100,
		"Number of locks to use for the client cache. "+
			"Increasing this value may improve performance during Vault client creation, but requires more memory. "+
			"When the value is <= 0 the number of locks will be set to the number of logical CPUs of the run host. "+
			"Also set from environment variable VSO_CLIENT_CACHE_NUM_LOCKS.")
	flag.StringVar(&clientCachePersistenceModel, "client-cache-persistence-model", defaultPersistenceModel,
		fmt.Sprintf(
			"The type of client cache persistence model that should be employed. "+
				"Also set from environment variable VSO_CLIENT_CACHE_PERSISTENCE_MODEL. "+
				"choices=%v", []string{persistenceModelDirectUnencrypted, persistenceModelDirectEncrypted, persistenceModelNone}))
	flag.IntVar(&vdsOptions.MaxConcurrentReconciles, "max-concurrent-reconciles-vds", defaultVaultDynamicSecretsConcurrency,
		"Maximum number of concurrent reconciles for the VaultDynamicSecrets controller. Deprecated in favor of -max-concurrent-reconciles.")
	flag.IntVar(&controllerOptions.MaxConcurrentReconciles, "max-concurrent-reconciles", defaultSyncableSecretsConcurrency,
		"Maximum number of concurrent reconciles for each controller. "+
			"Also set from environment variable VSO_MAX_CONCURRENT_RECONCILES.")
	flag.BoolVar(&uninstall, "uninstall", false, "Run in uninstall mode")
	flag.IntVar(&preDeleteHookTimeoutSeconds, "pre-delete-hook-timeout-seconds", 60,
		"Pre-delete hook timeout in seconds")
	flag.DurationVar(&minRefreshAfterHVSA, "min-refresh-after-hvsa", time.Second*30,
		"Minimum duration between HCPVaultSecretsApp resource reconciliation.")
	flag.StringVar(&globalTransformationOpts, "global-transformation-options", "",
		fmt.Sprintf("Set global secret transformation options as a comma delimited string. "+
			"Also set from environment variable VSO_GLOBAL_TRANSFORMATION_OPTIONS. "+
			"Valid values are: %v", []string{"exclude-raw"}))
	flag.StringVar(&globalVaultAuthOpts, "global-vault-auth-options", "allow-default-globals",
		fmt.Sprintf("Set global vault auth options as a comma delimited string. "+
			"Also set from environment variable VSO_GLOBAL_VAULT_AUTH_OPTIONS. "+
			"Valid values are: %v", []string{"allow-default-globals"}))
	flag.DurationVar(&backoffInitialInterval, "backoff-initial-interval", time.Second*5,
		"Initial interval between retries on secret source errors. "+
			"All errors are tried using an exponential backoff strategy. "+
			"Also set from environment variable VSO_BACKOFF_INITIAL_INTERVAL.")
	flag.DurationVar(&backoffMaxInterval, "backoff-max-interval", time.Second*60,
		"Maximum interval between retries on secret source errors. "+
			"All errors are tried using an exponential backoff strategy. "+
			"Also set from environment variable VSO_BACKOFF_MAX_INTERVAL.")
	flag.DurationVar(&backoffMaxElapsedTime, "backoff-max-elapsed-time", 0,
		"Maximum elapsed time without a successful sync from the secret's source. "+
			"It's important to note that setting this option to anything other than "+
			"its default value of 0 will result in the secret sync no longer being retried after "+
			"reaching the max elapsed time without a successful sync. This could "+
			"All errors are tried using an exponential backoff strategy. "+
			"Also set from environment variable VSO_BACKOFF_MAX_ELAPSED_TIME.")
	flag.Float64Var(&backoffRandomizationFactor, "backoff-randomization-factor",
		backoff.DefaultRandomizationFactor,
		"Sets the randomization factor to add jitter to the interval between retries on secret "+
			"source errors. All errors are tried using an exponential backoff strategy. "+
			"Also set from environment variable VSO_BACKOFF_RANDOMIZATION_FACTOR.")
	flag.Float64Var(&backoffMultiplier, "backoff-multiplier",
		backoff.DefaultMultiplier,
		"Sets the multiplier for increasing the interval between retries on secret source errors. "+
			"All errors are tried using an exponential backoff strategy. "+
			"The value must be greater than zero. "+
			"Also set from environment variable VSO_BACKOFF_MULTIPLIER.")

	opts := zap.Options{
		Development: os.Getenv("VSO_LOGGER_DEVELOPMENT_MODE") != "",
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	// Parse environment variable options, prefixed with "VSO_"
	if err := vsoEnvOptions.Parse(); err != nil {
		os.Stderr.WriteString(fmt.Sprintf("Failed to process environment variable options: %q\n", err))
		os.Exit(1)
	}

	var globalTransOptsSet []string
	var globalVaultAuthOptsSet []string
	// Set options from env if any are set
	if vsoEnvOptions.OutputFormat != "" {
		outputFormat = vsoEnvOptions.OutputFormat
	}
	if vsoEnvOptions.ClientCacheSize != nil {
		cfc.ClientCacheSize = *vsoEnvOptions.ClientCacheSize
	}
	if vsoEnvOptions.ClientCacheNumLocks != nil {
		cfc.ClientCacheNumLocks = *vsoEnvOptions.ClientCacheNumLocks
	}
	if vsoEnvOptions.ClientCachePersistenceModel != "" {
		clientCachePersistenceModel = vsoEnvOptions.ClientCachePersistenceModel
	}
	if vsoEnvOptions.MaxConcurrentReconciles != nil {
		controllerOptions.MaxConcurrentReconciles = *vsoEnvOptions.MaxConcurrentReconciles
	}
	if len(vsoEnvOptions.GlobalTransformationOptions) > 0 {
		globalTransOptsSet = vsoEnvOptions.GlobalTransformationOptions
	} else if globalTransformationOpts != "" {
		globalTransOptsSet = strings.Split(globalTransformationOpts, ",")
	}
	if vsoEnvOptions.BackoffInitialInterval != 0 {
		backoffInitialInterval = vsoEnvOptions.BackoffInitialInterval
	}
	if vsoEnvOptions.BackoffMaxInterval != 0 {
		backoffMaxInterval = vsoEnvOptions.BackoffMaxInterval
	}
	if vsoEnvOptions.BackoffRandomizationFactor != 0 {
		backoffRandomizationFactor = vsoEnvOptions.BackoffRandomizationFactor
	}
	if vsoEnvOptions.BackoffMultiplier != 0 {
		backoffMultiplier = vsoEnvOptions.BackoffMultiplier
	}
	if len(vsoEnvOptions.GlobalVaultAuthOptions) > 0 {
		globalVaultAuthOptsSet = vsoEnvOptions.GlobalVaultAuthOptions
	} else if globalVaultAuthOpts != "" {
		globalVaultAuthOptsSet = strings.Split(globalVaultAuthOpts, ",")
	}

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

	if backoffMultiplier <= 0 {
		setupLog.Error(errors.New("invalid option"),
			fmt.Sprintf("Invalid backoff multiplier %f, must be greater than 0", backoffMultiplier))
		os.Exit(1)
	}

	backoffOpts := []backoff.ExponentialBackOffOpts{
		backoff.WithInitialInterval(backoffInitialInterval),
		backoff.WithMaxInterval(backoffMaxInterval),
		backoff.WithRandomizationFactor(backoffRandomizationFactor),
		backoff.WithMultiplier(backoffMultiplier),
		backoff.WithMaxElapsedTime(backoffMaxElapsedTime),
	}

	globalTransOptions := &helpers.GlobalTransformationOptions{}
	for _, v := range globalTransOptsSet {
		switch v {
		case "exclude-raw":
			globalTransOptions.ExcludeRaw = true
		default:
			setupLog.Error(fmt.Errorf("unsupported rendering option %q", v),
				"Invalid argument for --global-transformation-options")
			os.Exit(1)
		}
	}

	globalVaultAuthOptions := &common.GlobalVaultAuthOptions{}
	for _, v := range globalVaultAuthOptsSet {
		switch v {
		case "allow-default-globals":
			globalVaultAuthOptions.AllowDefaultGlobals = true
		default:
			setupLog.Error(fmt.Errorf("unsupported global vault auth option %q", v),
				"Invalid argument for --global-vault-auth-options")
			os.Exit(1)
		}
	}
	cfc.GlobalVaultAuthOptions = globalVaultAuthOptions

	config := ctrl.GetConfigOrDie()

	defaultClient, err := client.NewWithWatch(config, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		setupLog.Error(err, "Failed to instantiate a default Client")
		os.Exit(1)
	}

	// This is the code path where we do Helm uninstall, and decide the shutdownMode for ClientFactory
	if uninstall {
		cleanupLog.Info("commencing cleanup of finalizers")
		preDeleteDeadline := startTime.Add(time.Second * time.Duration(preDeleteHookTimeoutSeconds))
		preDeleteDeadlineCtx, cancel := context.WithDeadline(context.Background(), preDeleteDeadline)
		// Even though ctx will be expired, it is good practice to call its
		// cancellation functions in any case. Failure to do so may keep the
		// context and its parent alive longer than necessary.
		defer cancel()

		cleanupLog.Info("deleting finalizers")
		if err = controllers.RemoveAllFinalizers(preDeleteDeadlineCtx, defaultClient, cleanupLog); err != nil {
			cleanupLog.Error(err, "unable to remove finalizers")
			os.Exit(1)
		}

		os.Exit(0)
	}

	collectMetrics := metricsAddr != ""
	if collectMetrics {
		cfc.MetricsRegistry.MustRegister(
			metrics.NewBuildInfoGauge(versionInfo),
		)
		vclient.MustRegisterClientMetrics(cfc.MetricsRegistry)

		metric := prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: metrics.Namespace,
				Subsystem: "runtime",
				Name:      "config",
				Help:      "Vault Secrets Operator runtime config.",
				ConstLabels: map[string]string{
					"backoffInitialInterval":      backoffInitialInterval.String(),
					"backoffMaxInterval":          backoffMaxInterval.String(),
					"backoffMaxElapsedTime":       backoffMaxElapsedTime.String(),
					"backoffMultiplier":           fmt.Sprintf("%.2f", backoffMultiplier),
					"backoffRandomizationFactor":  fmt.Sprintf("%.2f", backoffRandomizationFactor),
					"clientCachePersistenceModel": clientCachePersistenceModel,
					"clientCacheSize":             strconv.Itoa(cfc.ClientCacheSize),
					"globalTransformationOptions": globalTransformationOpts,
					"globalVaultAuthOptions":      globalVaultAuthOpts,
					"maxConcurrentReconciles":     strconv.Itoa(controllerOptions.MaxConcurrentReconciles),
				},
			},
		)
		metric.Set(1)
		cfc.MetricsRegistry.MustRegister(metric)
	}

	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme: scheme,
		Client: client.Options{
			Cache: &client.CacheOptions{
				// disable caching of K8s Secrets to avoid OOM issues. Caching is not needed for
				// the operator.
				DisableFor: []client.Object{
					&corev1.Secret{},
				},
			},
		},
		Metrics: server.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer:          webhook.NewServer(webhook.Options{Port: 9443}),
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
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Unable to start manager")
		os.Exit(1)
	}
	ctx := ctrl.SetupSignalHandler()

	var requirements []labels.Requirement
	for _, k := range []string{helpers.ManagedByLabel, helpers.AppNameLabel} {
		val, ok := helpers.OwnerLabels[k]
		if !ok || val == "" {
			setupLog.Error(errors.New("invalid option"),
				fmt.Sprintf("Expected Owner label %q is not present, this is a bug", k))
			os.Exit(1)
		}

		if r, err := labels.NewRequirement(
			k, selection.Equals, []string{
				val,
			}); err != nil {
			setupLog.Error(err, "Failed to create label requirement")
			os.Exit(1)
		} else {
			requirements = append(requirements, *r)
		}
	}

	// secretsClient is used to interact with secrets that match the selector. This
	// client is useful to avoid caching all secrets in a cluster. The client will
	// cache only secrets that match the selector.
	secretsClient, err := helpers.NewSecretsClientForManager(ctx, mgr, labels.NewSelector().Add(requirements...))
	if err != nil {
		setupLog.Error(err, "Failed to create a Secrets client")
		os.Exit(1)
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
				fmt.Sprintf("Invalid cache persistence model %q", clientCachePersistenceModel))
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

	hmacValidator := helpers.NewHMACValidator(cfc.StorageConfig.HMACSecretObjKey)
	secretDataBuilder := helpers.NewSecretsDataBuilder()
	if err = (&controllers.VaultStaticSecretReconciler{
		Client:                      mgr.GetClient(),
		Scheme:                      mgr.GetScheme(),
		Recorder:                    mgr.GetEventRecorderFor("VaultStaticSecret"),
		SecretDataBuilder:           secretDataBuilder,
		SecretsClient:               secretsClient,
		HMACValidator:               hmacValidator,
		ClientFactory:               clientFactory,
		BackOffRegistry:             controllers.NewBackOffRegistry(backoffOpts...),
		GlobalTransformationOptions: globalTransOptions,
	}).SetupWithManager(mgr, controllerOptions); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultStaticSecret")
		os.Exit(1)
	}
	if err = (&controllers.VaultPKISecretReconciler{
		Client:                      mgr.GetClient(),
		Scheme:                      mgr.GetScheme(),
		ClientFactory:               clientFactory,
		SecretsClient:               secretsClient,
		HMACValidator:               hmacValidator,
		SyncRegistry:                controllers.NewSyncRegistry(),
		Recorder:                    mgr.GetEventRecorderFor("VaultPKISecret"),
		BackOffRegistry:             controllers.NewBackOffRegistry(backoffOpts...),
		GlobalTransformationOptions: globalTransOptions,
	}).SetupWithManager(mgr, controllerOptions); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultPKISecret")
		os.Exit(1)
	}
	if err = (&controllers.VaultAuthReconciler{
		Client:                 mgr.GetClient(),
		Scheme:                 mgr.GetScheme(),
		Recorder:               mgr.GetEventRecorderFor("VaultAuth"),
		ClientFactory:          clientFactory,
		GlobalVaultAuthOptions: globalVaultAuthOptions,
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
	// This allows the user to customize VDS concurrency independently.
	// It is mostly here to allow for backward compatibility from when we introduced the flag
	// `--max-concurrent-reconciles`.
	vdsOverrideOpts := controller.Options{}
	if vdsOptions.MaxConcurrentReconciles != defaultVaultDynamicSecretsConcurrency {
		setupLog.Info("The flag --max-concurrent-reconciles-vds has been deprecated, but will " +
			"still be honored to set the VDS controller concurrency, please use --max-concurrent-reconciles.")
		vdsOverrideOpts = vdsOptions
	} else {
		vdsOverrideOpts = controllerOptions
	}

	vdsReconciler := &controllers.VaultDynamicSecretReconciler{
		Client:                      mgr.GetClient(),
		Scheme:                      mgr.GetScheme(),
		Recorder:                    mgr.GetEventRecorderFor("VaultDynamicSecret"),
		ClientFactory:               clientFactory,
		SecretsClient:               secretsClient,
		HMACValidator:               hmacValidator,
		SyncRegistry:                controllers.NewSyncRegistry(),
		BackOffRegistry:             controllers.NewBackOffRegistry(backoffOpts...),
		GlobalTransformationOptions: globalTransOptions,
	}
	if err = vdsReconciler.SetupWithManager(mgr, vdsOverrideOpts); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "VaultDynamicSecret")
		os.Exit(1)
	}
	defer func() {
		if vdsReconciler.SourceCh != nil {
			close(vdsReconciler.SourceCh)
		}
	}()

	if err = (&controllers.HCPAuthReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "HCPAuth")
		os.Exit(1)
	}
	if err = (&controllers.HCPVaultSecretsAppReconciler{
		Client:                      mgr.GetClient(),
		Scheme:                      mgr.GetScheme(),
		Recorder:                    mgr.GetEventRecorderFor("HCPVaultSecretsApp"),
		SecretDataBuilder:           secretDataBuilder,
		SecretsClient:               secretsClient,
		HMACValidator:               hmacValidator,
		MinRefreshAfter:             minRefreshAfterHVSA,
		BackOffRegistry:             controllers.NewBackOffRegistry(backoffOpts...),
		GlobalTransformationOptions: globalTransOptions,
	}).SetupWithManager(mgr, controllerOptions); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "HCPVaultSecretsApp")
		os.Exit(1)
	}
	if err = (&controllers.SecretTransformationReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("SecretTransformation"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SecretTransformation")
		os.Exit(1)
	}
	if err = (&controllers.VaultAuthGlobalReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VaultAuthGlobal")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager",
		"gitVersion", versionInfo.GitVersion,
		"gitCommit", versionInfo.GitCommit,
		"gitTreeState", versionInfo.GitTreeState,
		"buildDate", versionInfo.BuildDate,
		"goVersion", versionInfo.GoVersion,
		"platform", versionInfo.Platform,
		"clientCachePersistenceModel", clientCachePersistenceModel,
		"clientCacheSize", cfc.ClientCacheSize,
		"backoffMultiplier", backoffMultiplier,
		"backoffMaxInterval", backoffMaxInterval,
		"backoffMaxElapsedTime", backoffMaxElapsedTime,
		"backoffInitialInterval", backoffInitialInterval,
		"backoffRandomizationFactor", backoffRandomizationFactor,
		"globalTransformationOptions", globalTransformationOpts,
		"globalVaultAuthOptions", globalVaultAuthOpts,
	)

	mgr.GetCache()

	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func shutDownOperator(ctx context.Context, c client.Client, mode vclient.ShutDownMode) error {
	cm, err := vclient.GetManagerConfigMap(ctx, c)
	if err != nil {
		return err
	}

	if err = vclient.SetShutDownMode(ctx, c, cm, mode); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			if ctx.Err() != nil {
				return fmt.Errorf("shutdown context canceled err=%s", ctx.Err())
			}
			return nil
		default:
			// Periodically check for shutDownStatus updates as the ClientFactory shutdown process can take a while
			time.Sleep(500 * time.Millisecond)
			cm, err = vclient.GetManagerConfigMap(ctx, c)
			if err != nil {
				return fmt.Errorf("failed to get the manager configmap err=%s", err)
			}
			status := vclient.GetShutDownStatus(cm)
			switch status {
			case vclient.ShutDownStatusDone:
				return nil
			case vclient.ShutDownStatusFailed:
				return fmt.Errorf("failed to shut down")
			}
		}
	}
}
