# 🔒 SYKIL : Security Analyzer

<p align="center">
  <strong>Smashing Vulnerabilities, Securing Code</strong>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+"></a>
  <a href="./LICENSE.md"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://fury.io"><img src="https://img.shields.io/badge/version-1.0.0-orange.svg" alt="Version"></a>
</p>

---

**SYKIL** adalah tools keamanan canggih berbasis CLI untuk mendeteksi kerentanan, bug, dan anomali dalam kode sumber Anda. Mendukung PHP, JavaScript, Python, Java, Ruby, dan berbagai framework modern.

## ✨ Fitur Utama

- 🔍 **53+ Security Rules** - Deteksi kerentanan OWASP Top 10 dan CVE spesifik.
- 🛡️ **10+ CVE Detection** - PHP2Shell, Next.js SSRF, Django SQLi, Spring RCE, dll.
- 🔧 **Auto-Fix Engine** - Perbaikan otomatis untuk 20+ jenis masalah.
- 📝 **Multi-Format Report** - Console berwarna, JSON, dan HTML.
- 🔐 **Credential Migration** - Migrasi otomatis hardcoded credentials ke `.env`.
- 💾 **Backup & Undo System** - Backup otomatis sebelum fix, bisa undo kapan saja.
- 📋 **Manual Fix Guide** - Panduan perbaikan manual untuk issue kompleks.
- 🔄 **Dry-Run Mode** - Preview fix tanpa mengubah file.
- 🎯 **Interactive Mode** - Konfirmasi manual per issue.

## 🚀 Instalasi

```bash
pip install sykil-security-analyzer
```

## 📖 Cara Penggunaan

### Scan Project
```bash
# Scan standar
sykil /path/to/project

# Ekspor ke format spesifik
sykil /path/to/project --export json
sykil /path/to/project --export html
sykil /path/to/project --export both
```

### Auto-Fix
```bash
# Preview perbaikan tanpa mengubah file
sykil --fix output/sykil_report_xxx.json --dry-run

# Jalankan perbaikan otomatis
sykil --fix output/sykil_report_xxx.json

# Jalankan perbaikan tanpa konfirmasi manual
sykil --fix output/sykil_report_xxx.json --yes
```

### Undo (Jika Terjadi Masalah)
```bash
# Lihat riwayat sesi perbaikan
sykil --list-sessions

# Kembalikan ke kondisi sebelum sesi terbaru
sykil --undo

# Kembalikan berdasarkan ID sesi spesifik
sykil --undo <session_id>
```

## 🛡️ Kerentanan yang Dideteksi

| Kategori | Contoh Kerentanan |
| :--- | :--- |
| **Injection** | SQL Injection, Command Injection, XSS, SSTI |
| **Authentication** | Hardcoded Credentials, Insecure Cookie, JWT Issues |
| **File Operations** | Path Traversal, Zip Slip, File Inclusion |
| **Deserialization** | Insecure Deserialization, Unsafe YAML Load, Pickle |
| **Configuration** | Debug Mode, Missing Security Headers, CORS |
| **Modern Framework** | React XSS, Next.js SSRF, Django SQLi, Laravel |

## 📄 Lisensi

Didistribusikan di bawah **MIT License** [LICENSE.md](./LICENSE.md).

## 🙏 Acknowledgments

- [OWASP Top 10](https://owasp.org)
- [MITRE CVE Database](https://mitre.org)
- Komunitas Open-Source Security Tools
