#!/usr/bin/env bash
set -euo pipefail

API='https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest'
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

api_get() {
  local headers=(
    -H 'Accept: application/vnd.github+json'
    -H 'X-GitHub-Api-Version: 2022-11-28'
  )
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    headers+=( -H "Authorization: Bearer $GITHUB_TOKEN" )
  fi
  curl --fail --silent --show-error --location \
    --retry 3 --retry-all-errors \
    "${headers[@]}" \
    "$API"
}

release_json=''
if [[ "${GITHUB_EVENT_NAME:-}" == 'schedule' ]]; then
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  expected="$(date -u +%Y-%m-%dT22:00:00Z)"
  if [[ "$now" < "$expected" ]]; then
    expected="$(date -u -d 'yesterday' +%Y-%m-%dT22:00:00Z)"
  fi
  for attempt in $(seq 1 19); do
    release_json="$(api_get)"
    published_at="$(jq -er '.published_at' <<<"$release_json")"
    if [[ "$published_at" == "$expected" || "$published_at" > "$expected" ]]; then
      break
    fi
    if [[ "$attempt" -eq 19 ]]; then
      echo "No fresh upstream release published after $expected" >&2
      exit 1
    fi
    echo "Latest upstream release is $published_at; waiting for today's upstream build to finish..."
    sleep 600
  done
else
  release_json="$(api_get)"
fi

tag="$(jq -er '.tag_name' <<<"$release_json")"
published_at="$(jq -er '.published_at' <<<"$release_json")"

echo "Using upstream release $tag ($published_at)"

asset_url() {
  local name="$1"
  jq -er --arg name "$name" '.assets[] | select(.name == $name) | .browser_download_url' <<<"$release_json"
}

download_asset() {
  local name="$1"
  local url
  url="$(asset_url "$name")"
  curl --fail --silent --show-error --location \
    --retry 3 --retry-all-errors \
    -o "$TMP_DIR/$name" "$url"
}

download_asset geosite.dat
download_asset geosite.dat.sha256sum
download_asset direct-list.txt

(
  cd "$TMP_DIR"
  sha256sum --check geosite.dat.sha256sum
)

go run ./cmd/geosite2autoproxy \
  -input "$TMP_DIR/geosite.dat" \
  -reference "$TMP_DIR/direct-list.txt" \
  -output cn.txt \
  -base64-output cn.base64.txt

head -n 1 cn.txt | grep -Fx '[AutoProxy 0.2.9]' >/dev/null
rule_count="$(grep -cvE '^(!|\[|$)' cn.txt)"
if (( rule_count < 1000 )); then
  echo "Generated rule count is suspiciously low: $rule_count" >&2
  exit 1
fi
base64 --decode cn.base64.txt | cmp --silent - cn.txt

echo "Generated and validated $rule_count AutoProxy rules from upstream release $tag"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "upstream_tag=$tag" >> "$GITHUB_OUTPUT"
  echo "rule_count=$rule_count" >> "$GITHUB_OUTPUT"
fi
