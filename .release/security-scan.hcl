# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

container {
	dependencies = true
	alpine_secdb = true
	secrets {
		all = true
	}
}

binary {
	secrets {
		all = true
	}
	go_modules   = true
	osv          = true
	oss_index    = false
	nvd          = false
	triage {
		suppress {
			vulnerabilities = [
				// GO-2022-0635 is of low severity, and VSO isn't using the affected functionalities
				// Upgrading to latest version of go-secure-stdlib is not possible at this time.
				// The required functionality was inadvertently dropped from
				// github.com/hashicorp/go-secure-stdlib/awsutil during the migration to aws-sdk-go-v2.
				"GO-2022-0635"
			]
		}
	}
}
