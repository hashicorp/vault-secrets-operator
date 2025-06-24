# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

binary {
	go_stdlib  = true // Scan the Go standard library used to build the binary.
	go_modules = true // Scan the Go modules included in the binary.
	osv        = true // Use the OSV vulnerability database.
	oss_index  = true // And use OSS Index vulnerability database.

	secrets {
		all = true
	}

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

container {
	dependencies = true // Scan any installed packages for vulnerabilities.
	osv          = true // Use the OSV vulnerability database.

	secrets {
		all = true
	}
}
