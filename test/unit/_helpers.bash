# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# chart_dir returns the directory for the chart
chart_dir() {
    echo ${BATS_TEST_DIRNAME}/../../chart/
}
