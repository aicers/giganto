#!/usr/bin/env bash
# Fetch shared docs-theme release assets into docs/.theme/.
#
# Reads repo, version, and template from docs/theme.toml.
# Requires the GitHub CLI (gh) to download release archives.
#
# Override via environment variables:
#   THEME_REPO=aicers/docs-theme THEME_VERSION=0.1.0 THEME_TEMPLATE=manual \
#     scripts/fetch-theme.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
THEME_TOML="$ROOT_DIR/docs/theme.toml"
DEST="$ROOT_DIR/docs/.theme"

# ---------------------------------------------------------------------------
# Require gh CLI
# ---------------------------------------------------------------------------
if ! command -v gh >/dev/null 2>&1; then
  echo "Error: the GitHub CLI (gh) is required. Install it from https://cli.github.com/" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Parse docs/theme.toml (key = "value" format, ignores section headers)
# ---------------------------------------------------------------------------
parse_toml_value() {
  sed -n '/^\[/d; s/^'"$1"'[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$THEME_TOML" | head -1
}

REPO="${THEME_REPO:-$(parse_toml_value repo)}"
VERSION="${THEME_VERSION:-$(parse_toml_value version)}"
TEMPLATE="${THEME_TEMPLATE:-$(parse_toml_value template)}"

if [ -z "$REPO" ] || [ -z "$VERSION" ] || [ -z "$TEMPLATE" ]; then
  echo "Error: could not read repo/version/template from $THEME_TOML" >&2
  exit 1
fi

TAG="$VERSION"

# ---------------------------------------------------------------------------
# Skip if already installed with matching repo/version/template
# ---------------------------------------------------------------------------
MARKER="$DEST/.meta"
parse_meta_value() {
  sed -n '/^\[/d; s/^'"$1"'[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$MARKER" | head -1
}
if [ -f "$MARKER" ]; then
  if [ "$(parse_meta_value repo)" = "$REPO" ] \
    && [ "$(parse_meta_value version)" = "$TAG" ] \
    && [ "$(parse_meta_value template)" = "$TEMPLATE" ]; then
    echo "Theme $REPO@$TAG (template=$TEMPLATE) already installed, skipping."
    exit 0
  fi
fi

echo "Fetching docs-theme $REPO@$TAG (template=$TEMPLATE) ..."

# ---------------------------------------------------------------------------
# Download release archive via gh
# ---------------------------------------------------------------------------
TMPDIR_DL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_DL"' EXIT

gh release download "$TAG" --repo "$REPO" --archive tar.gz --dir "$TMPDIR_DL"

# ---------------------------------------------------------------------------
# Extract the archive
# ---------------------------------------------------------------------------
ARCHIVE="$(find "$TMPDIR_DL" -name '*.tar.gz' | head -1)"
if [ -z "$ARCHIVE" ]; then
  echo "Error: no tar.gz archive found in $TMPDIR_DL" >&2
  exit 1
fi

tar -xzf "$ARCHIVE" -C "$TMPDIR_DL"

# The archive extracts into a directory named REPO_NAME-TAG
REPO_NAME="$(echo "$REPO" | sed 's|.*/||')"
EXTRACTED=""
for d in "$TMPDIR_DL/$REPO_NAME"-*; do
  if [ -d "$d" ]; then
    EXTRACTED="$d"
    break
  fi
done

if [ -z "$EXTRACTED" ] || [ ! -d "$EXTRACTED" ]; then
  echo "Error: could not find extracted directory in $TMPDIR_DL" >&2
  ls -la "$TMPDIR_DL" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Stage into a temporary directory and validate before replacing docs/.theme/
# ---------------------------------------------------------------------------
STAGE="$(mktemp -d)"
# Clean up staging dir together with the download dir
trap 'rm -rf "$TMPDIR_DL" "$STAGE"' EXIT

# Copy template directory into staging area
TEMPLATE_DIR="$EXTRACTED/templates/$TEMPLATE"
if [ -d "$TEMPLATE_DIR" ]; then
  cp -R "$TEMPLATE_DIR/." "$STAGE/"
else
  echo "Error: templates/$TEMPLATE/ not found in archive" >&2
  exit 1
fi

# Copy shared assets (brand, fonts, etc.) flattened into the staging root
if [ -d "$EXTRACTED/shared" ]; then
  cp -R "$EXTRACTED/shared/." "$STAGE/"
else
  echo "Error: shared/ not found in archive" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Validate that all theme assets required by this repository are present
# ---------------------------------------------------------------------------
MISSING=0
for asset in \
  "mkdocs-base.yml" \
  "pdf" \
  "brand.svg" \
  "fonts" \
  "styles/lists.css" \
  "styles/pdf.css"; do
  if [ ! -e "$STAGE/$asset" ]; then
    echo "Error: required theme asset missing: $asset" >&2
    MISSING=1
  fi
done

if [ "$MISSING" -ne 0 ]; then
  echo "Validation failed — existing docs/.theme/ has been preserved." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Validation passed — replace docs/.theme/ with the staged content
# ---------------------------------------------------------------------------
rm -rf "$DEST"
mv "$STAGE" "$DEST"

# Record installed version so subsequent runs can skip re-download
cat > "$MARKER" <<EOF
[theme]
repo = "$REPO"
template = "$TEMPLATE"
version = "$TAG"
EOF

echo "Theme installed to $DEST"
