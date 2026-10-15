#!/bin/bash
# survey_point.sh — ambil snapshot RSSI semua AP di SATU titik berdiri
# pakai:  sudo bash survey_point.sh <nama_titik>
# contoh: sudo bash survey_point.sh depan
#         sudo bash survey_point.sh kanan
set -e
NAME="${1:?pakai: survey_point.sh <nama_titik>}"
DIR=/root/wifi-deauth-improved/survey
SAFE=$(echo "$NAME" | tr -c 'a-zA-Z0-9_-' '_')
OUT="$DIR/point_${SAFE}.log"
mkdir -p "$DIR"
cd /root/wifi-deauth-improved

{
echo "=== POINT: $NAME  $(date '+%F %T') ==="
python3 wifi-deauth2.py -i wlx28ee52133183 -s 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
} > "$OUT"

echo "[+] Tersimpan: $OUT"
grep -A2 "Signal ranking" "$OUT" | head -3 || true
