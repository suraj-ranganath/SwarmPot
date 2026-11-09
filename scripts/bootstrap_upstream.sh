#!/usr/bin/env bash
# Fetch the three pinned upstream systems into vendor/.
#
# vendor/ is gitignored: these are reproducible third-party checkouts, and the
# exact commits a run used are recorded in vendor.lock.json and in every
# episode manifest. Re-run this script to rebootstrap a fresh clone.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p vendor

fetch() {
    local name="$1" url="$2" commit="$3" dir="vendor/$1"
    if [ ! -d "$dir/.git" ]; then
        git clone "$url" "$dir"
    fi
    git -C "$dir" fetch --quiet origin "$commit" 2>/dev/null || git -C "$dir" fetch --quiet origin
    git -C "$dir" checkout --quiet "$commit"
    echo "$name -> $(git -C "$dir" rev-parse HEAD)"
}

fetch cve-bench https://github.com/uiuc-kang-lab/cve-bench 9fb3e068f260b00dd899ef87951b88e9c60061f1
fetch ARTEMIS   https://github.com/Stanford-Trinity/ARTEMIS f309242d2a74493cd41aa3f8b02cec4d3fdd479d
fetch cowrie    https://github.com/cowrie/cowrie ea9513eda9ea0dac05f6ace7db84ca95e0571501

echo
echo "Next: scripts/build_images.sh"
