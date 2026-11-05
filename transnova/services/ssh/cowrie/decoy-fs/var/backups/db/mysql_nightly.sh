#!/bin/sh
# Nightly logical backup of the orders database.
# SYNTHETIC DECOY CONTENT - lab honeypot, not a real system.
set -e
BACKUP_DIR=/var/backups/db
STAMP=$(date +%F)
mysqldump --defaults-extra-file=/var/backups/db/.my.cnf \
  --single-transaction --routines orders | gzip > "$BACKUP_DIR/orders_$STAMP.sql.gz"
find "$BACKUP_DIR" -name 'orders_*.sql.gz' -mtime +14 -delete
