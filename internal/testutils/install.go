// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package testutils

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

var onlyOneSignalHandler = make(chan struct{})

var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

// InstallVSO installs a Vault Secrets Operator Helm release.
func InstallVSO(t *testing.T, ctx context.Context, extraArgs ...string) error {
	t.Helper()
	return RunHelm(t, ctx, time.Minute*5, nil, nil, append([]string{"install"}, extraArgs...)...)
}

// UpgradeVSO upgrades a Vault Secrets Operator Helm release.
func UpgradeVSO(t *testing.T, ctx context.Context, extraArgs ...string) error {
	t.Helper()
	return RunHelm(t, ctx, time.Minute*5, nil, nil, append([]string{"upgrade"}, extraArgs...)...)
}

// UninstallVSO uninstalls a Vault Secrets Operator Helm release.
func UninstallVSO(t *testing.T, ctx context.Context, extraArgs ...string) error {
	t.Helper()
	return RunHelm(t, ctx, time.Minute*3, nil, nil, append([]string{"uninstall"}, extraArgs...)...)
}

// RunHelm runs the helm command with the given arguments.
func RunHelm(t *testing.T, ctx context.Context, timeout time.Duration, stdout, stderr io.Writer, args ...string) error {
	t.Helper()
	return RunCommandWithTimeout(t, ctx, timeout, stdout, stderr, "helm", args...)
}

// RunKind runs the kind command with the given arguments.
func RunKind(t *testing.T, ctx context.Context, args ...string) error {
	t.Helper()
	return RunCommandWithTimeout(t, ctx, time.Minute*5, nil, nil, "kind", args...)
}

// RunCommandWithTimeout runs a command with a timeout. If the timeout is 0, the command will run indefinitely.
func RunCommandWithTimeout(t *testing.T, ctx context.Context, timeout time.Duration, stdout, stderr io.Writer, name string, args ...string) error {
	t.Helper()
	var ctx_ context.Context
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx_, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	} else {
		ctx_ = ctx
	}

	cmd := exec.CommandContext(ctx_, name, args...)
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = os.Stdout
	}
	if stderr != nil {
		cmd.Stderr = stderr
	} else {
		cmd.Stderr = os.Stderr
	}

	t.Logf("Running command %q", cmd)
	return cmd.Run()
}

// SetupSignalHandler registers for SIGTERM and SIGINT. A context is returned
// which is canceled on one of these signals. If a second signal is caught, the program
// is terminated with exit code 1.
// Can only be called once.
func SetupSignalHandler() (context.Context, context.CancelFunc) {
	close(onlyOneSignalHandler) // panics when called twice

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return ctx, cancel
}
