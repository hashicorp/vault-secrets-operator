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
                "GO-2022-0635",
                // GO-2026-5932 flags the golang.org/x/crypto/openpgp subpackage as unmaintained/unsafe.
                // VSO does not import or call openpgp anywhere; confirmed via `go mod why` (package not
                // needed by the main module) and `govulncheck -mode=binary`, which found the symbol
                // unreachable in the built binary. False positive from module-level (non-symbol) matching.
                "GO-2026-5932",
                // GO-2026-6443 is a panic in google.golang.org/grpc's xDS server routing interceptor when
                // a request is missing both the :authority and Host headers. VSO pulls in grpc only as an
                // indirect dependency of its cloud client libraries and does not run a gRPC server, let
                // alone configure xDS routing, so the vulnerable code path is unreachable.
                "GO-2026-6443",
                // GHSA-2v4p-qf9q-27wj is the GitHub Security Advisory ID for the same google.golang.org/grpc
                // xDS server routing panic covered by GO-2026-6443 above. VSO only pulls in grpc as an
                // indirect dependency of its cloud client libraries and does not run a gRPC server or
                // configure xDS routing, so the vulnerable code path is unreachable.
                "GHSA-2v4p-qf9q-27wj",
            ]
        }
    }
}

container {
    dependencies = true // Scan any installed packages for vulnerabilities.
    osv          = true // Use the OSV vulnerability database.

    triage {
        suppress {
			// The OSV scanner will trip on several packages that are included in the
			// the UBI images. This is due to RHEL using the same base version in the
			// package name for the life of the distro regardless of whether or not
			// that version has been patched for security. Rather than enumate ever
			// single CVE that the OSV scanner will find (several tens) we'll ignore
			// the base UBI packages.
			paths = [
				"usr/lib/sysimage/rpm/*",
				"var/lib/rpm/*",
			]
        }
    }

    secrets {
        all = true
    }
}
