#!/usr/bin/env bash
# Re-run the write-side checks (CU, DV) from source and compare with results/.
# Nothing is built or executed: the checks only parse the applications' source.
# Usage: ./reproduce.sh <dir containing the application source trees>
#   expected subdirectories: mattermost-v11.5.1, mattermost-v11.5.2, mattermost-v12.0.1,
#   vikunja-v2.7.1, kimai-2.56.0, kimai-2.57.0, kimai-2.58.0, kimai-2.59.0
set -euo pipefail
A=${1:?usage: ./reproduce.sh <apps dir>}
OUT=${OUT:-out}; mkdir -p "$OUT"
for v in v11.5.1 v11.5.2 v12.0.1; do
  python3 checks/cu_check.py "$A/mattermost-$v/server/channels" "$OUT/cu-mattermost-$v.json" > /dev/null
  python3 checks/cu_check.py "$A/mattermost-$v/server/channels" "$OUT/cu-all-mattermost-$v.json" --all > /dev/null
done
python3 checks/cu_check_vikunja.py "$A/vikunja-v2.7.1/pkg/models" "$OUT/cu-vikunja-v2.7.1.json" > /dev/null
python3 checks/cu_check_vikunja.py "$A/vikunja-v2.7.1/pkg/models" "$OUT/cu-all-vikunja-v2.7.1.json" --all > /dev/null
for v in 2.56.0 2.57.0 2.58.0 2.59.0; do
  python3 checks/php_derive_check.py "$A/kimai-$v" "$OUT/derive-kimai-$v.json" > /dev/null
done
for f in "$OUT"/*.json; do
  b=$(basename "$f")
  if cmp -s "$f" "results/$b"; then echo "same      $b"; else echo "DIFFERENT $b"; fi
done
