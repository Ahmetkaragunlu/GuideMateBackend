#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MANIFEST="$PROJECT_ROOT/src/main/resources/demo/tour-cover-sources.tsv"
MEDIA_ROOT="$HOME/.guidemate/guidemate-demo-media"
SOURCE_ROOT="$MEDIA_ROOT/_sources"
MAX_BYTES=5242880
EXPECTED_ROWS=24

if [[ ! -f "$MANIFEST" ]]; then
  echo "Demo tour cover manifest is missing." >&2
  exit 2
fi
if [[ -L "$HOME/.guidemate" || -L "$MEDIA_ROOT" ]]; then
  echo "Refusing to prepare media through a symbolic link." >&2
  exit 2
fi

mkdir -p "$SOURCE_ROOT"
find "$SOURCE_ROOT" -maxdepth 1 -type f \( -name '*.jpg' -o -name 'SHA256SUMS' \) -delete
row_count=0
checksum_file=$(mktemp)
trap 'rm -f "$checksum_file"' EXIT

while IFS=$'\t' read -r slug city file_title description_url license license_url artist download_url; do
  if [[ "$slug" == "slug" ]]; then
    continue
  fi
  if [[ -z "$slug" || -z "$download_url" || -z "$license" ]]; then
    echo "Demo tour cover manifest contains an incomplete row." >&2
    exit 2
  fi

  target="$SOURCE_ROOT/$slug.jpg"
  temporary=$(mktemp "$SOURCE_ROOT/$slug.XXXXXX.tmp")
  if ! curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 \
      -A 'GuideMateDemoMediaPreparation/1.0 (local development)' \
      "$download_url" -o "$temporary"; then
    rm -f "$temporary"
    echo "Could not download the locked Wikimedia source for $slug." >&2
    exit 1
  fi

  mime_type=$(file -b --mime-type "$temporary")
  size_bytes=$(wc -c < "$temporary" | tr -d ' ')
  if [[ "$mime_type" != "image/jpeg" || "$size_bytes" -le 0 || "$size_bytes" -gt "$MAX_BYTES" ]]; then
    rm -f "$temporary"
    echo "Downloaded media for $slug is not a supported JPEG fixture." >&2
    exit 2
  fi

  mv -f "$temporary" "$target"
  shasum -a 256 "$target" >> "$checksum_file"
  row_count=$((row_count + 1))
done < "$MANIFEST"

if [[ "$row_count" -ne "$EXPECTED_ROWS" ]]; then
  echo "Expected $EXPECTED_ROWS tour cover sources but prepared $row_count." >&2
  exit 2
fi

mv -f "$checksum_file" "$SOURCE_ROOT/SHA256SUMS"
trap - EXIT
cp "$MANIFEST" "$MEDIA_ROOT/ATTRIBUTION.tsv"
chmod -R u+rwX,go-rwx "$MEDIA_ROOT"

printf 'prepared_sources=%s\n' "$row_count"
printf 'media_root=%s\n' "$MEDIA_ROOT"
