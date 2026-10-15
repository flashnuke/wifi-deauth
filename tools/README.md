# Arah AP dari Survey Multi-Titik (Walk-Survey)

Fitur Tier-0/C: menentukan **arahan perkiraan** tiap AP
("di depan, kanan, belakang, setelah WiFi X") dari perbedaan
RSSI di beberapa titik berdiri. Tanpa hardware tambahan.

## Prinsip
- Berdiri di beberapa titik dengan label arah (depan/kanan/...).
- Tiap titik: scan RSSI semua AP (`-s` + kolom Signal ranking).
- AP yang lokasinya di arah X akan terkuat saat berdiri di titik X.
- Direction_compute menjumlahkan vektor bobot p=10^((RSSI-max)/10)
  ke arah tiap titik → bearing + confidence (0..1).

## Pakai
```bash
cd /root/wifi-deauth-improved

# 1. Survey — berdiri di titiknya, jalankan (±65 dtk per titik):
sudo bash survey_point.sh depan
sudo bash survey_point.sh kanan
sudo bash survey_point.sh belakang
sudo bash survey_point.sh kiri
# titik lebih banyak = lebih akurat (bisa tambah: pojok-kanan=45 dst)

# 2. Hitung arah:
python3 direction_compute.py depan=0 kanan=90 belakang=180 kiri=270
# format: <nama_titik>=<bearing_derajat> — 0° = arah depan label kamu
```

## Membaca output
- `Arah` + `Sudut`: posisi perkiraan AP relatif terhadap titik survey.
- `Conf`: kekuatan kesimpulan arah. ≥0.50 ✓✓ yakin, 0.30-0.50 ✓ cukup,
  <0.30 + ΔdBm kecil → AP hampir sama jauh ke semua arah (omnidireksional).
- `ΔdBm`: selisih sinyal terkuat-terlemah antar titik. Makin besar,
  makin tajam arahnya. ≤3 dB = data tak cukup untuk menyimpulkan arah.
- Arah BUKAN posisi absolut: hanya relatif terhadap titik survey kamu.

## Batasan (jujur)
- Multipath & dinding membuat bearing kasar (typ. ±30-45°, bukan ±5°).
- Jangan pakai titik yang jaraknya beda jauh dari asal (jadi campur
  jarak + arah). Jaga radius ±3-5 m dari satu titik acuan.
- Frekuensi 5 GHz lebih peka halangan → gradien lebih tajam, lebih bagus
  untuk arah, tapi gampang hilang di balik dinding.
- Untuk presisi derajat butuh antena array (AoA) / Wi2SAR — tier D.

## File
- `survey_point.sh`     — snapshot RSSI 1 titik -> survey/point_<nama>.log
- `direction_compute.py` — gabungkan semua titik -> tabel arah
- `survey/`             — data mentah tiap titik
