#!/usr/bin/env sh
# Fetch shared docs-theme manual assets into docs/.theme/.
#
# Expected layout in the docs-theme archive:
#   templates/manual/   -> docs/.theme/          (mkdocs-base.yml, styles/, pdf/)
#   shared/             -> docs/.theme/shared/   (brand.svg, fonts/, styles/)
#
# Override repo or version via environment variables:
#   THEME_REPO=aicers/docs-theme THEME_VERSION=0.1.0 scripts/fetch-theme.sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
THEME_TOML="$ROOT_DIR/docs/theme.toml"
DEST="$ROOT_DIR/docs/.theme"

# ---------------------------------------------------------------------------
# Parse docs/theme.toml (simple key = "value" format)
# ---------------------------------------------------------------------------
parse_toml_value() {
  sed -n "s/^$1[[:space:]]*=[[:space:]]*\"\(.*\)\"/\1/p" "$THEME_TOML" | head -1
}

REPO="${THEME_REPO:-$(parse_toml_value repo)}"
VERSION="${THEME_VERSION:-$(parse_toml_value version)}"

if [ -z "$REPO" ] || [ -z "$VERSION" ]; then
  echo "Error: could not read repo/version from $THEME_TOML" >&2
  exit 1
fi

# Normalise: add leading 'v' only when downloading if the tag uses one,
# but also try without.  The archive URL works with the exact tag name.
TAG="$VERSION"
ARCHIVE_URL="https://github.com/$REPO/archive/refs/tags/$TAG.tar.gz"

echo "Fetching docs-theme $REPO@$TAG ..."

# ---------------------------------------------------------------------------
# Download & extract
# ---------------------------------------------------------------------------
TMPDIR_DL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_DL"' EXIT

ARCHIVE="$TMPDIR_DL/theme.tar.gz"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL -o "$ARCHIVE" "$ARCHIVE_URL"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$ARCHIVE" "$ARCHIVE_URL"
else
  echo "Error: curl or wget is required" >&2
  exit 1
fi

tar -xzf "$ARCHIVE" -C "$TMPDIR_DL"

# The archive extracts into a directory named REPO_NAME-TAG (e.g. docs-theme-0.1.0)
REPO_NAME="$(echo "$REPO" | sed 's|.*/||')"
EXTRACTED="$TMPDIR_DL/$REPO_NAME-$TAG"

if [ ! -d "$EXTRACTED" ]; then
  # Try without leading 'v' in directory name
  EXTRACTED="$TMPDIR_DL/$REPO_NAME-$(echo "$TAG" | sed 's/^v//')"
fi

if [ ! -d "$EXTRACTED" ]; then
  echo "Error: could not find extracted directory in $TMPDIR_DL" >&2
  ls -la "$TMPDIR_DL" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Install into docs/.theme/
# ---------------------------------------------------------------------------
rm -rf "$DEST"
mkdir -p "$DEST"

# Copy manual template
if [ -d "$EXTRACTED/templates/manual" ]; then
  cp -R "$EXTRACTED/templates/manual/." "$DEST/"
else
  echo "Error: templates/manual/ not found in archive" >&2
  exit 1
fi

# Copy shared assets (brand, fonts, etc.)
if [ -d "$EXTRACTED/shared" ]; then
  cp -R "$EXTRACTED/shared" "$DEST/shared"
else
  echo "Warning: shared/ not found in archive, skipping" >&2
fi

echo "Theme installed to $DEST"
