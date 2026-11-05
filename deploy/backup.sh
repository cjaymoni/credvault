#!/usr/bin/env bash
# Consistent backup of the credvault database.
#
# Vaults cannot be recovered without this file: the server holds only
# ciphertext and there is no password reset, so a lost database is lost data
# for every account on it. Run from cron as root, and keep a copy off this
# machine.
#
# Usage: ./backup.sh [destination-directory]   (default: /var/backups/credvault)
set -euo pipefail

DEST="${1:-/var/backups/credvault}"
VOLUME="credvault_data"
# Pinned; pulls sqlite at run time, so this needs network access.
SQLITE_IMAGE="alpine:3.20"
RETAIN_DAYS="${RETAIN_DAYS:-30}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="credvault-${STAMP}.db"

if [ "$(id -u)" -ne 0 ]; then
  echo "backup: run as root — the database directory is owned by the container's uid" >&2
  exit 1
fi

if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
  echo "backup: docker volume '$VOLUME' not found; is the stack up?" >&2
  exit 1
fi

mkdir -p "$DEST"
chmod 700 "$DEST"

# VACUUM INTO takes a read transaction, so this is consistent and safe while
# the server is running. A plain file copy is not: in WAL mode the most recent
# commits live in credvault.db-wal, which a copy of the .db alone would miss.
#
# The volume is mounted read-write because SQLite needs to create the -shm
# file to open a WAL database; nothing here modifies the data.
docker run --rm \
  -v "${VOLUME}:/data" \
  -v "${DEST}:/backup" \
  "$SQLITE_IMAGE" \
  sh -c "apk add --no-cache sqlite >/dev/null && \
         sqlite3 /data/credvault.db \"VACUUM INTO '/backup/${ARCHIVE}'\""

chmod 600 "${DEST}/${ARCHIVE}"
echo "backup: wrote ${DEST}/${ARCHIVE}"

# Prune old backups. Matches only this script's own naming.
find "$DEST" -maxdepth 1 -name 'credvault-*.db' -type f -mtime "+${RETAIN_DAYS}" -print -delete
