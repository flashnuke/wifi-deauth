#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
direction_compute.py — hitung ARAH perkiraan tiap AP dari survey multi-titik.

Cara pakai (berdiri di tiap titik, jalankan survey_point.sh <nama>, lalu):
  python3 direction_compute.py depan=0 kanan=90 belakang=180 kiri=270

Argumen: <nama_titik>=<bearing_derajat>, 0 = arah depan (sesuai label kamu.
Sudut searah jarum jam dilihat dari titik asal survey.

Model: vektor beban sinyal  V = sum_i p_i * u(theta_i)
       p_i = 10^((RSSI_i - max_RSSI)/10)   (linear, ternormalisasi)
       arah = atan2(V) ; keyakinan = |V| / sum(p_i)
Titik tempat AP tidak terdeteksi dianggap -95 dBm.
"""
import math
import os
import re
import sys
from glob import glob

SURVEY_DIR = os.environ.get("SURVEY_DIR", "/root/wifi-deauth-improved/survey")
MISSING_RSSI = -95

LINE_RE = re.compile(
    r"^\s*\d+\.\s+(.+?)\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s+(\d+)\s+(-?\d+)\s*dBm",
    re.M,
)
POINT_RE = re.compile(r"^=== POINT:\s*(\S+)\s+", re.M)

DIR_LABELS = [
    (0, "depan"), (45, "depan-kanan"), (90, "kanan"), (135, "belakang-kanan"),
    (180, "belakang"), (225, "belakang-kiri"), (270, "kiri"), (315, "depan-kiri"),
]


def label_of(bearing: float) -> str:
    best = min(DIR_LABELS, key=lambda d: abs((bearing - d[0] + 180) % 360 - 180))
    return best[1]


def parse_point(path: str):
    """-> (point_name, {mac: (ssid, rssi)})"""
    text = open(path, encoding="utf-8", errors="ignore").read()
    m = POINT_RE.search(text)
    name = m.group(1) if m else os.path.basename(path)
    data = {}
    for sm in LINE_RE.finditer(text):
        ssid, mac, _ch, rssi = sm.groups()
        r = int(rssi)
        mac = mac.lower()
        if mac not in data or r > data[mac][1]:
            data[mac] = (ssid.strip(), r)
    return name, data


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        sys.exit(2)
    points = []  # (name, bearing)
    for a in argv[1:]:
        if "=" not in a:
            print(f"[!] argumen salah: {a} (format: nama=bearing)")
            sys.exit(2)
        n, b = a.split("=", 1)
        points.append((n, float(b)))

    # baca log per titik
    surveys = {}  # name -> {mac: (ssid, rssi)}
    for name, _ in points:
        matches = glob(f"{SURVEY_DIR}/point_{re.sub(r'[^a-zA-Z0-9_-]', '_', name)}.log")
        if not matches:
            print(f"[!] log titik '{name}' tidak ada di {SURVEY_DIR}/ "
                  f"— jalankan dulu: sudo bash survey_point.sh {name}")
            sys.exit(1)
        pname, data = parse_point(matches[0])
        if not data:
            print(f"[!] {matches[0]} tidak berisi baris ranking — scan gagal?")
            sys.exit(1)
        surveys[name] = data

    macs = set()
    for d in surveys.values():
        macs |= set(d)

    results = []
    for mac in macs:
        ssid = next((d[mac][0] for d in surveys.values() if mac in d), mac)
        r_vals = []
        vx = vy = 0.0
        wsum = 0.0
        max_r = max((surveys[n][mac][1] for n, _ in points if mac in surveys[n]),
                    default=MISSING_RSSI)
        for name, bearing in points:
            r = surveys[name][mac][1] if mac in surveys[name] else MISSING_RSSI
            p = 10 ** ((r - max_r) / 10.0)
            rad = math.radians(bearing)
            vx += p * math.cos(rad)
            vy += p * math.sin(rad)
            wsum += p
            r_vals.append((r, name))
        mag = math.hypot(vx, vy)
        conf = mag / wsum if wsum else 0.0
        abearing = math.degrees(math.atan2(vy, vx)) % 360
        strongest = max(r_vals, key=lambda t: t[0])
        spread = strongest[0] - min(r for r, _ in r_vals)
        results.append(dict(mac=mac, ssid=ssid, bearing=abearing, conf=conf,
                            spread=spread, strong_rssi=strongest[0],
                            strong_pt=strongest[1], max_r=max_r))

    # urutkan: paling directional dulu
    results.sort(key=lambda x: (-x["spread"], -x["conf"]))

    print("=" * 78)
    print(f"ARAH PERKIRAAN AP (survey {len(points)} titik: "
          + ", ".join(f"{n}={int(b)}°" for n, b in points) + ")")
    print("Model: vektor beban RSSI | 0°=depan, 90°=kanan, 180°=belakang, 270°=kiri")
    print("=" * 78)
    hdr = f"{'MAC':<18} {'SSID':<20} {'Arah':<14} {'Sudut':>6} {'Conf':>5} {'ΔdBm':>5}  Catatan"
    print(hdr)
    print("-" * 78)
    for r in results:
        if r["conf"] >= 0.50:
            note, mark = "arah yakin", "✓✓"
        elif r["conf"] >= 0.30:
            note, mark = "arah cukup", "✓"
        elif r["spread"] <= 3:
            note, mark = "omnidireksional/rapat", "~"
        else:
            note, mark = "arah lemah/multipath", "!"
        label = label_of(r["bearing"])
        name = r["ssid"] if len(r["ssid"]) <= 19 else r["ssid"][:16] + "..."
        print(f"{r['mac']:<18} {name:<20} {label:<14} {r['bearing']:>5.0f}° "
              f"{r['conf']:>5.2f} {r['spread']:>4}  {mark} {note} "
              f"(terkuat di '{r['strong_pt']}' {r['strong_rssi']} dBm)")
    print("-" * 78)
    print("Catatan: conf=|vektor|/total bobot (0..1). ΔdBm kecil + conf rendah =")
    print("AP hampir sama jauh ke semua arah. Arah = relatif terhadap label titik.")
    print("=" * 78)


if __name__ == "__main__":
    main(sys.argv)
