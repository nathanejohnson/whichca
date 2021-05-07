#!/bin/bash
set -e
function supported_osarch {
	# Arguments:
	#   $1 - osarch - example, linux/amd64
	#
	# Returns:
	#   0 - supported
	#   * - not supported
	local osarch="$1"
	local -a valids=( $(go tool dist list) )
	in_array "${osarch}" "${valids[@]}"
	return $?
}

function in_array {
	local needle="$1"
	shift
	local -a haystack=("$@")

	for item in "$@"; do
		if [ "$item" == "$needle" ]; then
			return 0
		fi
	done
	return 1
}

function usage {
	cat <<EOF
${0} [ -s ] <binaryname> <release> [platforms...]

This builds go programs for one or more GOOS/GOARCH combinations.

If -s is passed, [platforms] is interpreted as goos/goarch combinations to skip.

Otherwise, [platforms] will be the goos/goarch combinations to build.

If no [platforms] are passed, it builds the popular platform / arch combinations.

Platforms must be specified with GOOS/GOARCH.  As an example:

    ${0} mybinary 1.0.0 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

This would compile the binary for linux and darwin platforms in both amd64 and arm64 arches.

    ${0} -s mybinary 1.0.0 darwin/arm64

This would compile for darwin, linux, windows, freebsd and openbsd for 386, arm64 and amd64
except for those combinations go tool dist list doesn't specify, and in this case darwin/arm64
will be skipped because we asked it to.

EOF
}


skip=0
while getopts s flag; do
	case "${flag}" in
		s) skip=1
		   ;;
		*) usage
		   exit 1
		   ;;
	esac
done
shift $((OPTIND - 1))
if [ "$#" -lt 2 ]; then
	usage
	exit 1
fi

GOOSES=( linux freebsd darwin windows openbsd )
GOARCHES=( 386 amd64 arm64 )
SKIPS=( )

if [ "${skip}" -eq 0 ] && [ "$#" -gt 2 ]; then
	GOOSES=( )
	GOARCHES=( )
	for combo in "${@:3}"; do
		IFS='/' read -r -a goosey <<< "$combo"
		if [ ${#goosey[@]} -ne 2 ]; then
			echo bad GOOS/GOARCH $combo
			exit 1
		fi
		if ! in_array "${goosey[0]}" "${GOOSES[@]}"; then
			GOOSES+=("${goosey[0]}")
		fi
		if ! in_array "${goosey[1]}" "${GOARCHES[@]}"; then
			GOARCHES+=("${goosey[1]}")
		fi

	done
else
	SKIPS=("${@:3}")
fi

echo GOOSES "${GOOSES[@]}"
echo GOARCHES "${GOARCHES[@]}"
echo SKIPS "${SKIPS[@]}"

NAME=${1}
RELEASE=${2}

echo "NAME: ${NAME} RELEASE: ${RELEASE}"
for GOOS in "${GOOSES[@]}"; do
	for GOARCH in "${GOARCHES[@]}"; do
		COMBO="${GOOS}/${GOARCH}"
		if ! supported_osarch "${COMBO}"; then
			echo skipping "${COMBO}" because invalid combo
			continue
		fi

		if in_array "${COMBO}" "${SKIPS[@]}"; then
			echo skipping "${COMBO}" because we were asked to
			continue
		fi
 		SUFFIX=""
		if [ ${GOOS} == "windows" ]; then
			SUFFIX=".exe"
		fi
		FILENAME="${NAME}_${RELEASE}_${GOOS}_${GOARCH}${SUFFIX}"
		echo building "${FILENAME}"
		GOOS=${GOOS} GOARCH=${GOARCH} CGO_ENABLED=0 go build -o "${FILENAME}"
	done
done
