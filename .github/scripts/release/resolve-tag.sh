#!/usr/bin/env bash
# Resolve a release tag to the commit it points at, and require that commit to be
# the one the caller expects.
#
#   bash resolve-tag.sh <tag> <expected-sha>
#
# The tag is asked for as refs/tags/<tag> and nothing else. A bare name can be a branch,
# and a branch called v2.0.2 must not pass for a tag, so the fetch names the tag ref and
# fails when only a branch of that name exists. The tag may be annotated: the commit is
# the peeled one. The commit is printed on stdout when it equals <expected-sha>; anything
# else, a missing tag, a tag that points elsewhere, a tag of the wrong shape, exits 1 and
# prints nothing, so a caller can never take an unverified commit from the output.
set -euo pipefail

tag="${1:?usage: resolve-tag.sh <tag> <expected-sha>}"
expected="${2:?usage: resolve-tag.sh <tag> <expected-sha>}"

if ! [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "::error::the tag is not v<major>.<minor>.<patch>" >&2
	exit 1
fi
if ! [[ "$expected" =~ ^[0-9a-f]{40}$ ]]; then
	echo "::error::the expected commit is not a full commit id" >&2
	exit 1
fi
if ! git fetch --no-tags --depth=1 origin "refs/tags/${tag}:refs/tags/${tag}" 2> /dev/null; then
	echo "::error::there is no tag ${tag} (a branch of that name is not a tag)" >&2
	exit 1
fi
tag_sha="$(git rev-parse "refs/tags/${tag}^{commit}")"
if [ "$tag_sha" != "$expected" ]; then
	echo "::error::${tag} points at ${tag_sha}, not at ${expected}; start the run from the tag" >&2
	exit 1
fi
printf '%s\n' "$tag_sha"
