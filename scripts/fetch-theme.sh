#!/usr/bin/env bash
# Fetch shared docs-theme assets into docs/.theme/.
#
# Reads repo, template, and exactly one source selector from docs/theme.toml:
# version (released tag) or rev (commit SHA for pre-release testing).
# When version is set, downloads a release via the GitHub CLI (gh).
# When rev is set, downloads that commit via gh api.
#
# Override via environment variables:
#   THEME_REPO=aicers/docs-theme THEME_VERSION=0.1.0 THEME_TEMPLATE=manual \
#     scripts/fetch-theme.sh
#   THEME_REPO=aicers/docs-theme THEME_REV=COMMIT_SHA THEME_TEMPLATE=manual \
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
REV="${THEME_REV:-$(parse_toml_value rev)}"
TEMPLATE="${THEME_TEMPLATE:-$(parse_toml_value template)}"

if [ -z "$REPO" ] || [ -z "$TEMPLATE" ]; then
  echo "Error: could not read repo/template from $THEME_TOML" >&2
  exit 1
fi

if [ -n "$VERSION" ] && [ -n "$REV" ]; then
  echo "Error: set exactly one of version (released theme) or rev (commit SHA), not both." >&2
  exit 1
fi

if [ -z "$VERSION" ] && [ -z "$REV" ]; then
  echo "Error: set exactly one of version (released theme) or rev (commit SHA)." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Skip if already installed with matching repo/template and version or rev
# ---------------------------------------------------------------------------
MARKER="$DEST/.meta"
parse_meta_value() {
  sed -n '/^\[/d; s/^'"$1"'[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$MARKER" | head -1
}
if [ -f "$MARKER" ]; then
  if [ -n "$REV" ]; then
    if [ "$(parse_meta_value repo)" = "$REPO" ] \
      && [ "$(parse_meta_value rev)" = "$REV" ] \
      && [ "$(parse_meta_value template)" = "$TEMPLATE" ]; then
      echo "Theme $REPO@$REV (template=$TEMPLATE) already installed, skipping."
      exit 0
    fi
  elif [ "$(parse_meta_value repo)" = "$REPO" ] \
    && [ "$(parse_meta_value version)" = "$VERSION" ] \
    && [ "$(parse_meta_value template)" = "$TEMPLATE" ]; then
    echo "Theme $REPO@$VERSION (template=$TEMPLATE) already installed, skipping."
    exit 0
  fi
fi

if [ -n "$REV" ]; then
  ARCHIVE_REF="$REV"
  echo "Fetching docs-theme $REPO@$REV (template=$TEMPLATE) ..."
else
  ARCHIVE_REF="$VERSION"
  echo "Fetching docs-theme $REPO@$VERSION (template=$TEMPLATE) ..."
fi

# ---------------------------------------------------------------------------
# Download archive
# ---------------------------------------------------------------------------
TMPDIR_DL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_DL"' EXIT

if [ -n "$REV" ]; then
  ARCHIVE="$TMPDIR_DL/archive.tar.gz"
  if ! gh api "repos/${REPO}/tarball/${ARCHIVE_REF}" > "$ARCHIVE"; then
    echo "Error: failed to download tarball for $REPO@$ARCHIVE_REF" >&2
    echo "Check that repo and rev are correct and the archive is reachable." >&2
    exit 1
  fi
else
  gh release download "$ARCHIVE_REF" --repo "$REPO" --archive tar.gz --dir "$TMPDIR_DL"
  ARCHIVE="$(find "$TMPDIR_DL" -name '*.tar.gz' | head -1)"
  if [ -z "$ARCHIVE" ]; then
    echo "Error: no tar.gz archive found in $TMPDIR_DL" >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Extract the archive
# ---------------------------------------------------------------------------
tar -xzf "$ARCHIVE" -C "$TMPDIR_DL"

EXTRACTED=""
for d in "$TMPDIR_DL"/*; do
  if [ -d "$d" ]; then
    if [ -n "$EXTRACTED" ]; then
      echo "Error: archive contains multiple top-level directories" >&2
      exit 1
    fi
    EXTRACTED="$d"
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

# Record installed source so subsequent runs can skip re-download
if [ -n "$REV" ]; then
  cat > "$MARKER" <<EOF
[theme]
repo = "$REPO"
template = "$TEMPLATE"
rev = "$REV"
EOF
else
  cat > "$MARKER" <<EOF
[theme]
repo = "$REPO"
template = "$TEMPLATE"
version = "$VERSION"
EOF
fi

echo "Theme installed to $DEST"
