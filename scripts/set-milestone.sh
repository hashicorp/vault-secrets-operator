#!/usr/bin/env bash
#
# This script sets the milestone for all PRs merged since the given tag.
# Usage: ./scripts/set-milestone.sh [START_TAG] [MILESTONE_NAME]
#
# Example: ./scripts/set-milestone.sh v1.3.0 "v1.4.0"
#
# The above example will set the milestone "v1.4.0" for all PRs merged since the tag "v1.3.0".

set -e -o pipefail

start_tag="$1"
milestone="$2"

if [[ -z "$start_tag" || -z "$milestone" ]]; then
  echo "Usage: $0 [START_TAG] [MILESTONE_NAME]"
  exit 1
fi

set -u

for n in $(git log origin ...${start_tag} | perl -n -e '/\(#(\d+)\)$/ && print "$1\n";' | sort -n)
  do gh pr edit --milestone "${milestone}" $n
done
