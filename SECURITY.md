# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Jika Anda menemukan kerentanan keamanan di **SYKIL Security Analyzer** itu sendiri (bukan kerentanan yang dideteksi oleh SYKIL), silakan report secara bertanggung jawab.

### Cara Report

1. **JANGAN** buat public issue di GitHub
2. Email ke: **security@anasfanu.com** (atau buat email khusus)
3. Atau gunakan [GitHub Security Advisory](https://github.com/anasfanu/sykil-security-analyzer/security/advisories/new)

### Informasi yang Perlu Disertakan

- Deskripsi kerentanan
- Langkah reproduksi (step-by-step)
- Versi SYKIL yang digunakan
- Impact potensial
- Suggested fix (jika ada)

### Timeline

- **Acknowledge**: Dalam 48 jam
- **Investigation**: Dalam 7 hari
- **Fix release**: Dalam 30 hari (tergantung severity)
- **Public disclosure**: Setelah fix dirilis

### Bug Bounty

Saat ini kami belum menyediakan bug bounty program, tetapi kami akan mencantumkan nama reporter di CHANGELOG.md (kecuali jika reporter ingin anonim).

## Security Best Practices

Saat menggunakan SYKIL:

1. **Jangan pernah** scan project tanpa izin
2. **Selalu** review hasil scan sebelum auto-fix
3. **Backup** code sebelum menjalankan auto-fix
4. **Test** hasil fix di environment development
5. **Report** false positive ke GitHub Issues

## Security Updates

Subscribe ke [GitHub Releases](https://github.com/anasfanu/sykil-security-analyzer/releases) untuk mendapat notifikasi security updates.