#!/usr/bin/env bash

set -eu -o pipefail

function enter () {
  local dir="${1:?need directory to enter}"
  printf '  in %s \t→\t' "$dir"
  cd -- "$dir"
}

function indent () {
  "$@" | grep -F 'package size' | while IFS= read -r line; do
    echo "     $line"
  done
}

echo 'in root: gitoxide CLI'
(enter legix-fsck && indent cargo diet -n --package-size-limit 10KB)
(enter legix-actor && indent cargo diet -n --package-size-limit 10KB)
(enter legix-archive && indent cargo diet -n --package-size-limit 10KB)
(enter legix-worktree-stream && indent cargo diet -n --package-size-limit 40KB)
(enter legix-utils && indent cargo diet -n --package-size-limit 10KB)
(enter legix-fs && indent cargo diet -n --package-size-limit 15KB)
(enter legix-pathspec && indent cargo diet -n --package-size-limit 30KB)
(enter legix-refspec && indent cargo diet -n --package-size-limit 30KB)
(enter legix-path && indent cargo diet -n --package-size-limit 25KB)
(enter legix-attributes && indent cargo diet -n --package-size-limit 25KB)
(enter legix-discover && indent cargo diet -n --package-size-limit 35KB)
(enter legix-index && indent cargo diet -n --package-size-limit 65KB)
(enter legix-worktree && indent cargo diet -n --package-size-limit 40KB)
(enter legix-quote && indent cargo diet -n --package-size-limit 10KB)
(enter legix-revision && indent cargo diet -n --package-size-limit 40KB)
(enter legix-bitmap && indent cargo diet -n --package-size-limit 10KB)
(enter legix-tempfile && indent cargo diet -n --package-size-limit 35KB)
(enter legix-lock && indent cargo diet -n --package-size-limit 25KB)
(enter legix-config && indent cargo diet -n --package-size-limit 140KB)
(enter legix-config-value && indent cargo diet -n --package-size-limit 20KB)
(enter legix-command && indent cargo diet -n --package-size-limit 10KB)
(enter legix-hash && indent cargo diet -n --package-size-limit 30KB)
(enter legix-chunk && indent cargo diet -n --package-size-limit 15KB)
(enter legix-features && indent cargo diet -n --package-size-limit 65KB)
(enter legix-ref && indent cargo diet -n --package-size-limit 55KB)
(enter legix-diff && indent cargo diet -n --package-size-limit 35KB)
(enter legix-traverse && indent cargo diet -n --package-size-limit 15KB)
(enter legix-url && indent cargo diet -n --package-size-limit 35KB)
(enter legix-validate && indent cargo diet -n --package-size-limit 10KB)
(enter legix-date && indent cargo diet -n --package-size-limit 25KB)
(enter legix-hashtable && indent cargo diet -n --package-size-limit 10KB)
(enter legix-filter && indent cargo diet -n --package-size-limit 35KB)
(enter legix-status && indent cargo diet -n --package-size-limit 30KB)
(enter legix-sec && indent cargo diet -n --package-size-limit 25KB)
(enter legix-credentials && indent cargo diet -n --package-size-limit 35KB)
(enter legix-prompt && indent cargo diet -n --package-size-limit 15KB)
(enter legix-object && indent cargo diet -n --package-size-limit 35KB)
(enter legix-commitgraph && indent cargo diet -n --package-size-limit 35KB)
(enter legix-pack && indent cargo diet -n --package-size-limit 140KB)
(enter legix-odb && indent cargo diet -n --package-size-limit 140KB)
(enter legix-protocol && indent cargo diet -n --package-size-limit 80KB)
(enter legix-packetline && indent cargo diet -n --package-size-limit 45KB)
(enter legix && indent cargo diet -n --package-size-limit 280KB)
(enter legix-transport && indent cargo diet -n --package-size-limit 95KB)
(enter legix-core && indent cargo diet -n --package-size-limit 160KB)
