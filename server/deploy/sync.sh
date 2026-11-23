#!/bin/sh
# Раз в минуту (orbita-sync.timer): забирает свежий main с GitHub в /opt/orbita.
# Если поменялся сервер (server/), перезапускает API.
set -eu
cd /opt/orbita
git fetch -q origin main
OLD=$(git rev-parse HEAD)
NEW=$(git rev-parse origin/main)
[ "$OLD" = "$NEW" ] && exit 0
git reset -q --hard "$NEW"
if git diff --name-only "$OLD" "$NEW" | grep -q '^server/'; then
  systemctl restart orbita
fi
echo "orbita: $OLD -> $NEW"
