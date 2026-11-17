#!/usr/bin/env bash
# Encrypted daily backup. Cron: 0 2 * * *  /opt/rea/scripts/backup.sh
set -euo pipefail
: "${DATABASE_URL:?}" "${BACKUP_PASSPHRASE:?}"
DIR="${BACKUP_DIR:-./backups}"; mkdir -p "$DIR"
OUT="$DIR/rea-$(date -u +%Y%m%dT%H%M%SZ).sql.gz.enc"
pg_dump --no-owner --format=plain "$DATABASE_URL" | gzip -9 \
  | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE -out "$OUT"
chmod 600 "$OUT"
find "$DIR" -name 'rea-*.sql.gz.enc' -mtime +"${RETENTION_DAYS:-14}" -delete
echo "Backup written: $OUT"
# Restore:  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE -in FILE | gunzip | psql "$DATABASE_URL"
