#!/usr/bin/env bash
# Sign the assets of a release.
#
#   bash sign-artifacts.sh <artifacts-dir> <installers-dir> <out-dir>
#
# Everything the script is given is data. The artifacts are what the build jobs
# uploaded, downloaded outside the checkout, one folder per architecture; the
# installers are the two scripts copied out of the checkout into a folder of their
# own. Each folder must hold exactly the expected names, as regular files and not
# links, and anything else (an extra name, a link, a folder, a file that could be
# imported as code) fails BEFORE the key is read or anything is written.
#
# Then the verified files are copied flat into <out-dir>, which must not exist yet,
# and signed there: one detached signature each, plus SHA256SUMS of the four assets
# and its own signature, and the result must be exactly the files of a release. The signer is the trusted script of the checkout, run with
# `python3 -I` (SIGN_PYTHON, the interpreter of a venv with the pinned library) so
# that nothing of the data directories or the working directory is imported. The key
# comes from GLYNDOR_RELEASE_ED25519_KEY, never from an argument.
set -euo pipefail

artifacts="${1:?usage: sign-artifacts.sh <artifacts-dir> <installers-dir> <out-dir>}"
installers="${2:?usage: sign-artifacts.sh <artifacts-dir> <installers-dir> <out-dir>}"
out="${3:?usage: sign-artifacts.sh <artifacts-dir> <installers-dir> <out-dir>}"
python="${SIGN_PYTHON:-python3}"
archs=(x86_64 arm64)
scripts=(setup-agent.sh update-agent.sh)

die() {
	echo "::error::$1"
	exit 1
}

for dir in "$artifacts" "$installers" "$out"; do
	case "$dir" in
		/*) ;;
		*) die "the directory $dir must be an absolute path" ;;
	esac
done
real_dir() { if [ ! -d "$1" ] || [ -L "$1" ]; then die "$1 is not a directory"; fi; }
real_dir "$artifacts"
real_dir "$installers"
if [ -e "$out" ] || [ -L "$out" ]; then die "$out exists; the output directory must be new"; fi

listing() { find "$1" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort; }
sorted() { printf '%s\n' "$@" | LC_ALL=C sort; }
regular() { if [ ! -f "$1" ] || [ -L "$1" ]; then die "$1 is not a regular file"; fi; }

[ "$(listing "$artifacts")" = "$(sorted "${archs[@]}")" ] || die "$artifacts must hold exactly: ${archs[*]}"
[ "$(listing "$installers")" = "$(sorted "${scripts[@]}")" ] || die "$installers must hold exactly: ${scripts[*]}"

assets=()
for arch in "${archs[@]}"; do
	folder="$artifacts/$arch"
	real_dir "$folder"
	name="helmly-agent-linux-$arch"
	[ "$(listing "$folder")" = "$name" ] || die "$folder must hold exactly: $name"
	regular "$folder/$name"
	assets+=("$folder/$name")
done
for name in "${scripts[@]}"; do
	regular "$installers/$name"
	assets+=("$installers/$name")
done

# Only now is anything written, and only now is the key needed.
: "${GLYNDOR_RELEASE_ED25519_KEY:?the signing key is not set}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is not set}"
mkdir "$out"
names=()
for asset in "${assets[@]}"; do
	cp "$asset" "$out/"
	names+=("$(basename "$asset")")
done
for name in "${names[@]}"; do
	"$python" -I "$GITHUB_WORKSPACE/.github/scripts/sign.py" "$out/$name"
done
(cd "$out" && sha256sum "${names[@]}" > SHA256SUMS)
"$python" -I "$GITHUB_WORKSPACE/.github/scripts/sign.py" "$out/SHA256SUMS"

# What was produced is exactly what a release publishes: the four assets, their
# signatures, the sums and their signature, each a regular file, and nothing else. The
# names are built from the architectures and the scripts above and carry no version of
# their own; the version is bound by the tag, which the workflow has already resolved to
# the commit it runs at, and by Cargo.toml, which verify has already compared with it.
want=("${names[@]}")
for name in "${names[@]}"; do want+=("$name.sig"); done
want+=(SHA256SUMS SHA256SUMS.sig)
[ "$(listing "$out")" = "$(sorted "${want[@]}")" ] || die "$out does not hold exactly the files of a release"
for name in "${want[@]}"; do regular "$out/$name"; done
