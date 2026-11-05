"""
Test Anti-False-Positive
========================

Test ini memastikan SYKIL TIDAK mendeteksi false positive di file Python-nya sendiri.

Kenapa test ini PENTING?
- Mencegah kasus seperti yang Anda alami (16 false positive di fixer.py)
- Memastikan filter docstring & string literal bekerja
- Memberikan confidence bahwa SYKIL bisa scan dirinya sendiri

Cara menjalankan:
    pytest tests/test_no_false_positive.py -v
"""

from pathlib import Path
from sykil_analyzer.scanner import SecurityScanner


# Path ke folder package SYKIL
SYKIL_PACKAGE_DIR = Path(__file__).parent.parent / "sykil_analyzer"


def test_no_false_positive_on_fixer():
    """
    Test KRITIS: fixer.py TIDAK boleh punya false positive
    
    File fixer.py punya banyak string literal dengan kata kunci berbahaya
    seperti 'eval()', 'document.write()', dll. Tapi itu HANYA string,
    bukan kode yang dieksekusi.
    """
    scanner = SecurityScanner()
    fixer_path = SYKIL_PACKAGE_DIR / "fixer.py"
    
    issues = scanner.scan_file(str(fixer_path))
    
    # ASSERT: Tidak boleh ada issue sama sekali
    assert len(issues) == 0, (
        f"\n\n❌ False positive terdeteksi di fixer.py!\n"
        f"Jumlah issue: {len(issues)}\n"
        f"\nIssue pertama:\n"
        f"  ID: {issues[0]['id']}\n"
        f"  Line: {issues[0]['line']}\n"
        f"  Content: {issues[0]['content'][:100]}\n"
        f"\nIni berarti filter anti-false-positive belum bekerja dengan benar."
    )


def test_no_false_positive_on_config():
    """
    Test: config.py TIDAK boleh punya false positive
    
    File config.py menyebut '.env' di banyak tempat (string literal),
    tapi itu bukan file yang terekspos.
    """
    scanner = SecurityScanner()
    config_path = SYKIL_PACKAGE_DIR / "config.py"
    
    issues = scanner.scan_file(str(config_path))
    
    assert len(issues) == 0, (
        f"\n\n❌ False positive terdeteksi di config.py!\n"
        f"Jumlah issue: {len(issues)}\n"
        f"\nIssue pertama:\n"
        f"  ID: {issues[0]['id']}\n"
        f"  Line: {issues[0]['line']}\n"
        f"  Content: {issues[0]['content'][:100]}\n"
    )


def test_no_false_positive_on_scanner():
    """
    Test: scanner.py TIDAK boleh punya false positive
    
    File scanner.py punya list '.env' di ignored_files,
    tapi itu bukan file yang terekspos.
    """
    scanner = SecurityScanner()
    scanner_path = SYKIL_PACKAGE_DIR / "scanner.py"
    
    issues = scanner.scan_file(str(scanner_path))
    
    assert len(issues) == 0, (
        f"\n\n❌ False positive terdeteksi di scanner.py!\n"
        f"Jumlah issue: {len(issues)}\n"
        f"\nIssue pertama:\n"
        f"  ID: {issues[0]['id']}\n"
        f"  Line: {issues[0]['line']}\n"
        f"  Content: {issues[0]['content'][:100]}\n"
    )


def test_no_false_positive_on_reporter():
    """Test: reporter.py TIDAK boleh punya false positive"""
    scanner = SecurityScanner()
    reporter_path = SYKIL_PACKAGE_DIR / "reporter.py"
    
    issues = scanner.scan_file(str(reporter_path))
    
    assert len(issues) == 0, (
        f"\n\n❌ False positive terdeteksi di reporter.py!\n"
        f"Jumlah issue: {len(issues)}\n"
        f"\nIssue pertama:\n"
        f"  ID: {issues[0]['id']}\n"
        f"  Line: {issues[0]['line']}\n"
        f"  Content: {issues[0]['content'][:100]}\n"
    )


def test_no_false_positive_on_logger():
    """Test: logger.py TIDAK boleh punya false positive"""
    scanner = SecurityScanner()
    logger_path = SYKIL_PACKAGE_DIR / "logger.py"
    
    issues = scanner.scan_file(str(logger_path))
    
    assert len(issues) == 0, (
        f"\n\n❌ False positive terdeteksi di logger.py!\n"
        f"Jumlah issue: {len(issues)}\n"
        f"\nIssue pertama:\n"
        f"  ID: {issues[0]['id']}\n"
        f"  Line: {issues[0]['line']}\n"
        f"  Content: {issues[0]['content'][:100]}\n"
    )


def test_no_false_positive_on_cli():
    """Test: cli.py TIDAK boleh punya false positive"""
    scanner = SecurityScanner()
    cli_path = SYKIL_PACKAGE_DIR / "cli.py"
    
    issues = scanner.scan_file(str(cli_path))
    
    assert len(issues) == 0, (
        f"\n\n❌ False positive terdeteksi di cli.py!\n"
        f"Jumlah issue: {len(issues)}\n"
        f"\nIssue pertama:\n"
        f"  ID: {issues[0]['id']}\n"
        f"  Line: {issues[0]['line']}\n"
        f"  Content: {issues[0]['content'][:100]}\n"
    )


def test_no_false_positive_on_entire_package():
    """
    Test KOMPREHENSIF: Seluruh package SYKIL TIDAK boleh punya false positive
    
    Test ini scan SEMUA file .py di folder sykil_analyzer/ dan memastikan
    tidak ada false positive sama sekali.
    """
    scanner = SecurityScanner()
    
    # Dapatkan semua file .py di package
    python_files = []
    for py_file in SYKIL_PACKAGE_DIR.rglob("*.py"):
        if "__pycache__" not in str(py_file):
            python_files.append(py_file)
    
    # Scan semua file
    all_issues = []
    for py_file in python_files:
        issues = scanner.scan_file(str(py_file))
        for issue in issues:
            issue['source_file'] = str(py_file.name)
            all_issues.append(issue)
    
    # ASSERT: Tidak boleh ada issue sama sekali
    assert len(all_issues) == 0, (
        f"\n\n❌ False positive terdeteksi di package SYKIL!\n"
        f"Total file di-scan: {len(python_files)}\n"
        f"Total false positive: {len(all_issues)}\n"
        f"\nIssue pertama:\n"
        f"  File: {all_issues[0]['source_file']}\n"
        f"  ID: {all_issues[0]['id']}\n"
        f"  Line: {all_issues[0]['line']}\n"
        f"  Content: {all_issues[0]['content'][:100]}\n"
    )