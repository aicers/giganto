#!/usr/bin/env sh
# Fetch shared docs-theme release assets into docs/.theme/.
#
# Reads repo, version, and template from docs/theme.toml.
# Uses the GitHub releases API (set GH_TOKEN for private repos).
#
# Override via environment variables:
#   THEME_REPO=aicers/docs-theme THEME_VERSION=0.1.0 THEME_TEMPLATE=manual \
#     scripts/fetch-theme.sh
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
TEMPLATE="${THEME_TEMPLATE:-$(parse_toml_value template)}"

if [ -z "$REPO" ] || [ -z "$VERSION" ] || [ -z "$TEMPLATE" ]; then
  echo "Error: could not read repo/version/template from $THEME_TOML" >&2
  exit 1
fi

TAG="$VERSION"

# ---------------------------------------------------------------------------
# Skip if already installed with matching repo/version/template
# ---------------------------------------------------------------------------
MARKER="$DEST/.installed"
if [ -f "$MARKER" ] && [ "$(cat "$MARKER")" = "$REPO@$TAG/$TEMPLATE" ]; then
  echo "Theme $REPO@$TAG (template=$TEMPLATE) already installed, skipping."
  exit 0
fi

echo "Fetching docs-theme $REPO@$TAG (template=$TEMPLATE) ..."

# ---------------------------------------------------------------------------
# Helpers: HTTP download with optional GH_TOKEN auth
# ---------------------------------------------------------------------------
_curl() {
  if [ -n "${GH_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: token $GH_TOKEN" "$@"
  else
    curl -fsSL "$@"
  fi
}

_wget() {
  if [ -n "${GH_TOKEN:-}" ]; then
    wget -q --header="Authorization: token $GH_TOKEN" "$@"
  else
    wget -q "$@"
  fi
}

download() {
  _url="$1"; _out="$2"
  if command -v curl >/dev/null 2>&1; then
    _curl -o "$_out" "$_url"
  elif command -v wget >/dev/null 2>&1; then
    _wget -O "$_out" "$_url"
  else
    echo "Error: curl or wget is required" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Download release tarball via GitHub releases API
# ---------------------------------------------------------------------------
TMPDIR_DL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_DL"' EXIT

ARCHIVE="$TMPDIR_DL/theme.tar.gz"
RELEASE_TARBALL="https://api.github.com/repos/$REPO/tarball/$TAG"

download "$RELEASE_TARBALL" "$ARCHIVE"

tar -xzf "$ARCHIVE" -C "$TMPDIR_DL"

# The archive extracts into a directory named REPO_NAME-HASH or REPO_NAME-TAG
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
# Install into docs/.theme/ using the template path from theme.toml
# ---------------------------------------------------------------------------
rm -rf "$DEST"
mkdir -p "$DEST"

# Copy template directory
TEMPLATE_DIR="$EXTRACTED/templates/$TEMPLATE"
if [ -d "$TEMPLATE_DIR" ]; then
  cp -R "$TEMPLATE_DIR/." "$DEST/"
else
  echo "Error: templates/$TEMPLATE/ not found in archive" >&2
  exit 1
fi

# Copy shared assets (brand, fonts, etc.)
if [ -d "$EXTRACTED/shared" ]; then
  cp -R "$EXTRACTED/shared" "$DEST/shared"
else
  echo "Warning: shared/ not found in archive, skipping" >&2
fi

# Record installed version so subsequent runs can skip re-download
echo "$REPO@$TAG/$TEMPLATE" > "$MARKER"

echo "Theme installed to $DEST"
