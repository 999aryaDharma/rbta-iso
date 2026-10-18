#!/usr/bin/env bash
# RBTA CT pull-based CD dengan gerbang rilis.
#
# Cron memanggil skrip ini tiap N menit. Skrip mengambil origin/<branch> beserta tag;
# deploy HANYA bila commit ujung origin/<branch> memiliki tag `release-*`
# (git tag --points-at). Commit biasa diabaikan (dicatat sekali per SHA). Bila
# bertag: merge --ff-only ke SHA itu, rebuild image, up, lalu verifikasi /ready.
# Tulis "[skip cd]" di pesan commit bertag untuk tetap melewatinya.
#
# Variabel lingkungan (opsional):
#   RBTA_REPO_DIR  default $HOME/rbta
#   RBTA_CD_BRANCH default prod/final-dashboard-demo
#   RBTA_CD_LOG    default <stack>/cd.log
#   RBTA_HOST_PORT default 8010 (hanya untuk health check)
#   RBTA_CD_TAG_PATTERN default release-*
set -euo pipefail

REPO_DIR="${RBTA_REPO_DIR:-$HOME/rbta}"
BRANCH="${RBTA_CD_BRANCH:-prod/final-dashboard-demo}"
STACK_DIR="$REPO_DIR/deploy/ct"
LOG="${RBTA_CD_LOG:-$STACK_DIR/cd.log}"
LOCK="$STACK_DIR/.cd.lock"
SKIP_MARK="$STACK_DIR/.cd.last-untagged"
PORT="${RBTA_HOST_PORT:-8010}"
TAG_PATTERN="${RBTA_CD_TAG_PATTERN:-release-*}"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >>"$LOG"; }
fail() { log "ERROR $*"; exit 1; }

exec 9>"$LOCK"
flock -n 9 || exit 0  # run sebelumnya masih jalan; lewati jadwal ini

cd "$REPO_DIR" || fail "repo tidak ada: $REPO_DIR"
git fetch -q --tags origin "$BRANCH" || fail "git fetch gagal"
LOCAL="$(git rev-parse HEAD)"
REMOTE="$(git rev-parse "origin/$BRANCH")"
[ "$LOCAL" = "$REMOTE" ] && exit 0  # sudah terbaru, tanpa log bising

TAG="$(git tag --points-at "$REMOTE" --list "$TAG_PATTERN" | sort | tail -n 1)"
if [ -z "$TAG" ]; then
  # Commit biasa: abaikan. Log sekali per SHA agar cd.log tidak bising.
  if [ "$(cat "$SKIP_MARK" 2>/dev/null || true)" != "$REMOTE" ]; then
    log "SKIP $REMOTE tanpa tag $TAG_PATTERN (bukan rilis)"
    echo "$REMOTE" >"$SKIP_MARK"
  fi
  exit 0
fi

if git log -1 --format=%B "$REMOTE" | grep -q '\[skip cd\]'; then
  log "SKIP $REMOTE ($TAG) mengandung [skip cd]"
  exit 0
fi

log "DEPLOY $LOCAL -> $REMOTE ($TAG)"
# Merge ke SHA yang sudah dicek, bukan pull ujung branch (yang bisa saja commit baru tanpa tag).
git merge -q --ff-only "$REMOTE" || fail "git merge --ff-only gagal (riwayat menyimpang?)"
cd "$STACK_DIR"
# Dibaca compose sebagai build args; muncul di /ready (build_sha, release_tag).
export RBTA_CODE_SHA="$REMOTE" RBTA_RELEASE_TAG="$TAG" RBTA_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose build >>"$LOG" 2>&1 || fail "docker compose build gagal"
# Volume dibuat milik root; container jalan sebagai UID 10001 (idempoten).
docker run --rm -v rbta-ct-live:/s -v rbta-ct-archive:/a alpine chown -R 10001:10001 /s /a >>"$LOG" 2>&1 || fail "chown volume gagal"
docker compose up -d >>"$LOG" 2>&1 || fail "docker compose up gagal"

for i in $(seq 1 24); do
  if curl -fs -o /dev/null "http://127.0.0.1:$PORT/ready"; then
    log "OK $REMOTE ($TAG) live (ready dalam ~$((i * 5)) dtk)"
    exit 0
  fi
  sleep 5
done
fail "/ready tidak hijau 120 dtk setelah up; periksa docker compose logs"
