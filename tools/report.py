#!/usr/bin/env python3
"""report.py — Laporan ringkas semua run deauth + client/device finder.

Cara pakai:
  python3 report.py                 # semua run (run3, run4, target-a)
  python3 report.py run4            # filter substring nama log
  python3 report.py --no-net        # vendor lookup offline (cache saja)

Output: tabel per-AP + identifikasi device (OUI vendor) + eksekusi
klien. Hasil juga disimpan ke report.txt di folder yang sama.
"""
import re, os, sys, json, glob, subprocess, datetime

DIR = os.path.dirname(os.path.abspath(__file__))
ANSI = re.compile(r"\x1b\[[0-9;]*m")
USE_NET = "--no-net" not in sys.argv
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
CACHE = os.path.join(DIR, "oui_cache.json")
if not os.path.exists(CACHE):
    try:
        json.dump({"74:F2:FA": "Xiaomi Communications Co Ltd",
                   "94:F8:27": "Shanghai Imilab Technology Co.Ltd",
                   "7C:FA:80": "JiangSu Fulian Communication Technology"},
                  open(CACHE, "w"))
    except Exception:
        pass

def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return ""

def load(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return sh(["sudo", "cat", path])

# fallback offline utk OUI yang pernah terlihat + vendor umum
FALLBACK = {
    "74:F2:FA": "Xiaomi Communications Co Ltd",
    "94:F8:27": "Shanghai Imilab Technology Co.Ltd",
    "7C:FA:80": "JiangSu Fulian Communication Technology",
    "A8:93:4A": "CHONGQING FUGUI ELECTRONICS (Tenda OEM)",
    "78:8B:2A": "Zhen Shi (Shanghai) - IP camera",
    "D8:1E:DD": "GUANGDONG OPPO MOBILE TELECOMMUNICATIONS",
    "00:C3:0A": "Xiaomi Communications Co Ltd",
    "8C:AA:CE": "Xiaomi Communications Co Ltd",
    "C0:A8:10": "Intel Corporate",
    "B8:27:EB": "Raspberry Pi Foundation",
    "00:FA:DE": "Motorola (Moto G45)",
    "24:C0:13": "ZTE Corporation",
}

def vendor(oui):
    try:
        cache = json.load(open(CACHE))
    except Exception:
        cache = {}
    if oui in cache and not cache[oui].startswith("{"):
        return cache[oui]
    v = ""
    if USE_NET:
        import time
        for attempt in range(2):
            v = sh(["curl", "-s", "--max-time", "6",
                    f"https://api.macvendors.com/{oui}"]).strip()
            if v and not v.startswith("{") and not v.startswith("<"):
                break
            v = ""
            time.sleep(2.5)
        if v:
            cache[oui] = v
            try:
                json.dump(cache, open(CACHE, "w"))
            except Exception:
                pass
    if not v:
        v = FALLBACK.get(oui.upper(), "")
    return v

def is_random(mac):
    return bool(int(mac.split(":")[0], 16) & 0x02)

def device_of(mac):
    if is_random(mac):
        return "random MAC (Android/iOS private)"
    v = vendor(mac[:8].upper())
    return v if v else "vendor ?"

# ---------------------------------------------------------------- collect
sel = ARGS[0] if ARGS else None
logs = sorted(glob.glob(os.path.join(DIR, "*run*.log")) +
              glob.glob(os.path.join(DIR, "target-a*.log")))
if sel:
    logs = [l for l in logs if sel in os.path.basename(l)]
clog = load(os.path.join(DIR, "clients_seen.log"))

# clients_seen: epoch ssid bssid client
seen = {}
for line in clog.splitlines():
    p = line.split()
    if len(p) == 4 and p[0].isdigit():
        seen.setdefault(p[3], []).append((int(p[0]), p[1]))

lines = []
def out(s=""):
    lines.append(s)

out("=" * 70)
out("LAPORAN POC DEAUTH — CLIENT & DEVICE FINDER")
out(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} WIB")
out("=" * 70)

total_ap = with_client = 0
for logpath in logs:
    name = os.path.basename(logpath)
    log = ANSI.sub("", load(logpath))
    blocks = re.split(r"=== TARGET \[", log)
    if len(blocks) < 2 and "TargetAP" not in log:
        continue
    out()
    out(f"--- {name} ---")

    rows = []
    if len(blocks) >= 2:
        for b in blocks[1:]:
            ap = b.split("]")[0]
            ch = (re.search(r"ch=(\d+)", b) or [None, "?"])[1]
            bssid = (re.search(r"bssid=(\S+)", b) or [None, "?"])[1]
            disp = re.findall(r"Discovered \d+ client\(s\): ([^\n]+)", b)
            macs = []
            for d in disp:
                macs += [m.strip() for m in d.split(",") if m.strip()]
            conf = [int(x) for x in re.findall(r"Confirmed clients\s+(\d+)", b)]
            mx = max(conf) if conf else 0
            macs += [m for m, evs in seen.items()
                     if any(bb == bssid for _, bb in evs)]
            macs = sorted(set(macs))
            n = max(mx, len(macs))
            rc = (re.search(r"exit=(\d+)", b) or [None, "?"])[1]
            rows.append((ap, ch, bssid, n, macs, rc))
    else:
        # single target-style run
        ch = (re.search(r"ch=(\d+)", log) or [None, "?"])[1]
        bssid = (re.search(r"bssid=(\S+)", log) or [None, "?"])[1]
        conf = [int(x) for x in re.findall(r"Confirmed clients\s+(\d+)", log)]
        rc = (re.search(r"exit=(\d+)", log) or [None, "?"])[1]
        macs = [m for m, evs in seen.items() if any(bb == bssid for _, bb in evs)]
        rows.append(("TargetAP", ch, bssid, (max(conf) if conf else 0), sorted(macs), rc))

    out(f"{'AP':<17} {'ch':>3} {'rc':>3} {'kl':>2}  client MAC -> device")
    out("-" * 70)
    for ap, ch, bssid, n, macs, rc in rows:
        total_ap += 1
        if n:
            with_client += 1
        if macs:
            first = True
            for m in macs:
                tag = ap if first else ""
                first = False
                out(f"{tag:<17} {ch:>3} {rc:>3} {n:>2}  {m} -> {device_of(m)}")
        else:
            out(f"{ap:<17} {ch:>3} {rc:>3} {n:>2}  {'-' if not n else '(count only, MAC tak ke-log)'}")

# ---------------------------------------------------------------- summary
out()
out("=" * 70)
out(f"RINGKASAN: {with_client}/{total_ap} AP terdeteksi client")
out("-" * 70)
out("SEMUA CLIENT UNIK -> DEVICE:")
by_mac = {}
for m, evs in seen.items():
    by_mac[m] = sorted(set(bb for _, bb in evs))
for m in sorted(by_mac, key=lambda x: x):
    out(f"  {m}  {device_of(m):<38} AP: {', '.join(by_mac[m])}")
out("=" * 70)

txt = "\n".join(lines)
print(txt)
try:
    with open(os.path.join(DIR, "report.txt"), "w") as f:
        f.write(txt + "\n")
except Exception:
    pass
