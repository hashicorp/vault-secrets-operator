// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package version

import (
	apimachineryversion "k8s.io/apimachinery/pkg/version"
)

// the following variables are meant to be set at build time from 'ldflags'
var (
	Major        = ""
	Minor        = ""
	GitVersion   = ""
	GitCommit    = ""
	GitTreeState = ""
	BuildDate    = ""
	GoVersion    = ""
	Compiler     = ""
	Platform     = ""
)

func Version() apimachineryversion.Info {
	return apimachineryversion.Info{
		Major:        Major,
		Minor:        Minor,
		GitVersion:   GitVersion,
		GitCommit:    GitCommit,
		GitTreeState: GitTreeState,
		BuildDate:    BuildDate,
		GoVersion:    GoVersion,
		Compiler:     Compiler,
		Platform:     Platform,
	}
}
