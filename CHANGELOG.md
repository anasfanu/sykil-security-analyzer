# Changelog

Semua perubahan signifikan pada project SYKIL : Security Analyzer akan didokumentasikan di file ini.

Format berdasarkan [Keep a Changelog](https://keepachangelog.com/id-ID/1.0.0/),
dan project ini mengikuti [Semantic Versioning](https://semver.org/lang/id/).

## [Unreleased]

### Added
- Persiapan struktur package untuk PyPI
- Dokumentasi CHANGELOG.md

## [1.0.0] - 2026-11-04

### Added
- **53+ Security Rules** untuk deteksi kerentanan
  - 30 rules standar (SEC-001 s/d SEC-030)
  - 3 rules debug detection (SEC-031 s/d SEC-033)
  - 10 rules injection modern (SEC-034 s/d SEC-043)
  - 10 rules CVE spesifik (CVE-2024-* dan CVE-2026-*)
- **Auto-Fix Engine** untuk 20+ jenis kerentanan
  - Level 1: Deterministic Fix (10 rules)
  - Level 2: Context-Aware Fix (9 rules)
  - Special Logic: SEC-001 (Hardcoded Credentials migration)
  - Special Logic: SEC-043 (Unsafe YAML Deserialization)
- **Backup & Undo System**
  - Backup otomatis sebelum fix
  - Session tracking untuk undo
  - Command `sykil --list-sessions` dan `sykil --undo`
- **Multi-Format Report**
  - Console output dengan warna
  - JSON export
  - HTML export dengan panduan manual
- **Manual Fix Guide**
  - Panduan detail untuk 13 rules kompleks
  - Contoh kode before/after
  - Langkah-langkah perbaikan
  - Link referensi OWASP dan dokumentasi resmi
- **Konfigurasi Terpusat**
  - File `.env` untuk konfigurasi path output/backup/log
  - Default location: `C:\Sykil_Security_Analyzer\`
  - Bisa diubah sesuai kebutuhan user
- **Anti-False-Positive System**
  - Docstring detection untuk file Python
  - String literal detection
  - F-string detection
  - Python string check detection
  - `@nosec` comment bypass

### Security
- Deteksi kerentanan OWASP Top 10
- Deteksi CVE spesifik (PHP2Shell, Next.js SSRF, Django SQLi, dll)
- Deteksi debug mode yang tertinggal di production
- Deteksi insecure deserialization (YAML, Pickle, Marshal)
- Deteksi Server-Side Template Injection (SSTI)
- Deteksi Prototype Pollution (JavaScript)
- Deteksi NoSQL Injection

### Technical
- Python 3.8+ compatibility
- Cross-platform (Windows, Linux, macOS)
- No external dependencies (pure Python stdlib)
- Modular architecture (scanner, reporter, fixer, logger, config)
- Comprehensive logging system (app.log + error.log)
- Session management untuk undo capability

### Documentation
- README.md dengan contoh penggunaan lengkap
- Inline documentation di semua module
- Manual fix guide untuk kerentanan kompleks
- Error messages yang informatif

## [0.9.0] - 2026-10-28

### Added
- Initial beta release
- Basic scanning functionality
- 30 security rules
- Auto-fix untuk 10 rules
- JSON dan HTML report export

### Known Issues
- False positive pada file Python (docstring dan string literal)
- Belum ada undo capability
- Belum ada konfigurasi terpusat

---

## Tipe Perubahan

- **Added** → Fitur baru
- **Changed** → Perubahan pada fitur yang ada
- **Deprecated** → Fitur yang akan dihapus di versi mendatang
- **Removed** → Fitur yang sudah dihapus
- **Fixed** → Perbaikan bug
- **Security** → Perbaikan kerentanan keamanan