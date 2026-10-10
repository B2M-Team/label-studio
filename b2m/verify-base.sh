#!/usr/bin/env bash
# Fail if a file this fork overwrites differs from the one in the pinned base image, i.e. the
# base moved and the patch would silently drop upstream changes. Run before bumping the base.
set -euo pipefail
BASE=$(sed -n 's/^FROM //p' "$(dirname "$0")/Dockerfile")
FILES=(label_studio/core/settings/base.py)   # existing files only; remote_user.py is new
for f in "${FILES[@]}"; do
  up=$(docker run --rm --platform linux/amd64 --entrypoint sh "$BASE" -c "sha256sum /label-studio/$f" | cut -d' ' -f1)
  git show "$(git describe --tags --abbrev=0 --match '[0-9]*' HEAD):$f" | sha256sum | cut -d' ' -f1 | grep -qx "$up" \
    && echo "ok   $f" || { echo "DIFF $f differs from the base image"; exit 1; }
done
