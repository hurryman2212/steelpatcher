#!/usr/bin/env sh
set -eu

script_dir=$(
	unset CDPATH
	cd -- "$(dirname -- "$0")" && pwd
)
fallback_version=0.1.0
tag_pattern='^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*(-rc[0-9][0-9]*)?$'

print_fallback_version() {
	if [ -f "$script_dir/PKG-INFO" ]; then
		version=$(sed -n 's/^Version: //p' "$script_dir/PKG-INFO" | head -n 1)
		if [ -n "$version" ]; then
			printf '%s\n' "$version"
			return
		fi
	fi
	printf '%s\n' "$fallback_version"
}

if [ "${1-}" = "-h" ] || [ "${1-}" = "--help" ]; then
	printf '%s\n' 'Usage: ./generate-version.sh'
	printf '%s\n' 'Print a PEP 440 version derived from the nearest Git version tag.'
	exit 0
fi
if [ "$#" -ne 0 ]; then
	printf 'unknown option: %s\n' "$1" >&2
	exit 2
fi

if ! command -v git >/dev/null 2>&1 ||
	! git -C "$script_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	print_fallback_version
	exit 0
fi

description=$(git -C "$script_dir" describe --tags --long --abbrev=7 \
	--match '[0-9]*.[0-9]*.[0-9]*' HEAD 2>/dev/null || :)
if [ -z "$description" ]; then
	print_fallback_version
	exit 0
fi

sha=${description##*-g}
tag_and_distance=${description%-g*}
distance=${tag_and_distance##*-}
tag=${tag_and_distance%-"$distance"}
if ! printf '%s' "$tag" | grep -Eq "$tag_pattern" ||
	! printf '%s' "$distance" | grep -Eq '^[0-9][0-9]*$' ||
	! printf '%s' "$sha" | grep -Eq '^[0-9A-Fa-f]{7,40}$'; then
	print_fallback_version
	exit 0
fi

base=$(printf '%s' "$tag" | sed 's/-rc/rc/')
dirty=""
if ! git -C "$script_dir" diff-index --quiet HEAD -- 2>/dev/null; then
	dirty=dirty
fi

if [ "$distance" -eq 0 ]; then
	if [ -n "$dirty" ]; then
		printf '%s+dirty\n' "$base"
	else
		printf '%s\n' "$base"
	fi
	exit 0
fi

if [ -n "$dirty" ]; then
	printf '%s.post0.dev%s+g%s.dirty\n' "$base" "$distance" "$sha"
else
	printf '%s.post0.dev%s+g%s\n' "$base" "$distance" "$sha"
fi
