#!/bin/bash
set -eu

VERSION="$(echo "${CI_COMMIT_TAG}" | sed -nE 's/v([0-9]+)\.([0-9]+)\.([0-9]+).*/\1.\2.\3/p')"
CHANGELOG="$(awk '
		BEGIN {
			flag = 0
		}
		/^## / {
			if (!flag) {
				flag = 1
				next
			} else
				exit
		}
		flag {
			print
		}
	' CHANGELOG.md)"

declare -a args
for dist in sentinel-proxy-*.tar.gz sentinel-proxy-*.tar.xz sentinel-proxy-*.zip; do
	URL="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/sentinel-proxy/${VERSION}/${dist}"
	curl --header "JOB-TOKEN: ${CI_JOB_TOKEN}" --upload-file "${dist}" "${URL}"
	args+=("--assets-link" "{\"name\":\"${dist}\",\"url\":\"${URL}\"}")
done

release-cli create \
	--name "Release ${CI_COMMIT_TAG#v}" \
	--tag-name "$CI_COMMIT_TAG" \
	--description "$CHANGELOG" \
	"${args[@]}"
