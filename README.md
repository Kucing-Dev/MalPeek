## Simple Malware Analyzer

Sebuah alat sederhana berbasis Python untuk analisis file biner secara statis. Cocok untuk pemula di bidang malware analysis, forensik digital, dan reverse engineering.

## 🔍 Fitur

Skrip ini digunakan untuk menganalisis file `.exe` secara statik:
- Menghitung hash (MD5, SHA1, SHA256)
- Mengekstrak strings dari file
- Mendeteksi string mencurigakan (keyword jaringan, API Windows, dll)

 ## 1. Persiapkan Lingkungan
Pastikan kamu punya:
- Python 3.7 atau lebih baru
- Command-line tool strings (di Linux/macOS biasanya sudah ada)
### Jika belum punya pefile, install dulu:
```
1pip install -r requirements.txt

```

### 1.Buat Virtual Environment (folder terisolasi)
```
python3 -m venv venv
source venv/bin/activate
pip install pefile
```

## 2. Jalankan Tool-nya
Pastikan kamu berada di folder yang sama dengan `Analis.py`

```
python Analis.py

```
Masukkan path file `.exe` yang ingin dianalisis saat diminta.

