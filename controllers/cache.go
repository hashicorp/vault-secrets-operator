// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func filterOldCacheRefs(cur, other client.Object) bool {
	return cur.GetUID() == other.GetUID() && cur.GetGeneration() > other.GetGeneration()
}

func filterAllCacheRefs(cur, other client.Object) bool {
	return cur.GetUID() == other.GetUID()
}
