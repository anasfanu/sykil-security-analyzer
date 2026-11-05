"""
Test Deteksi Rules (File Sample Version)
=========================================

Test ini memastikan rule-rule SYKIL bekerja dengan benar.
Konten test disimpan di file .sample untuk menghindari deteksi antivirus.

Cara menjalankan:
    pytest tests/test_rules_detection.py -v

Cara tambah test untuk rule baru:
    1. Buat file sample di tests/samples/
    2. Tambahkan test function di file ini
"""

import os
from pathlib import Path
from sykil_analyzer.scanner import SecurityScanner


# Path ke folder samples
SAMPLES_DIR = Path(__file__).parent / "samples"


def scan_sample_file(filename: str):
    """
    Scan file sample dan kembalikan list of issues
    
    Args:
        filename: Nama file sample (misal: 'sql_injection_vuln.php.sample')
    
    Returns:
        List of issues yang terdeteksi
    """
    sample_path = SAMPLES_DIR / filename
    
    if not sample_path.exists():
        raise FileNotFoundError(f"Sample file not found: {sample_path}")
    
    scanner = SecurityScanner()
    return scanner.scan_file(str(sample_path))


def assert_rule_detected_in_sample(filename: str, rule_id: str):
    """Assert bahwa rule tertentu TERDETEKSI di file sample"""
    issues = scan_sample_file(filename)
    rule_issues = [i for i in issues if i['id'] == rule_id]
    
    assert len(rule_issues) > 0, (
        f"\n\n❌ Rule {rule_id} TIDAK terdeteksi di {filename}!\n"
        f"All issues detected: {[i['id'] for i in issues]}\n"
        f"\nFile sample: {SAMPLES_DIR / filename}\n"
    )


def assert_rule_not_detected_in_sample(filename: str, rule_id: str):
    """Assert bahwa rule tertentu TIDAK terdeteksi di file sample"""
    issues = scan_sample_file(filename)
    rule_issues = [i for i in issues if i['id'] == rule_id]
    
    assert len(rule_issues) == 0, (
        f"\n\n❌ Rule {rule_id} terdeteksi sebagai false positive di {filename}!\n"
        f"Issues detected: {rule_issues}\n"
        f"\nFile sample: {SAMPLES_DIR / filename}\n"
    )


# =========================================================================
# TEST: SQL INJECTION (SEC-002)
# =========================================================================

def test_sec_002_detects_sql_injection():
    """Test: SQL Injection harus terdeteksi"""
    assert_rule_detected_in_sample('sql_injection_vuln.php.sample', 'SEC-002')


def test_sec_002_no_false_positive_on_safe_query():
    """Test: Prepared statement TIDAK boleh terdeteksi"""
    assert_rule_not_detected_in_sample('sql_injection_safe.php.sample', 'SEC-002')


# =========================================================================
# TEST: XSS (SEC-003)
# =========================================================================

def test_sec_003_detects_xss():
    """Test: XSS harus terdeteksi"""
    assert_rule_detected_in_sample('xss_vuln.php.sample', 'SEC-003')


def test_sec_003_no_false_positive_on_sanitized():
    """Test: Output yang sudah di-sanitize TIDAK boleh terdeteksi sebagai XSS"""
    assert_rule_not_detected_in_sample('xss_safe.php.sample', 'SEC-003')


# =========================================================================
# TEST: RCE / eval (SEC-004)
# =========================================================================

def test_sec_004_detects_eval():
    """Test: eval() harus terdeteksi"""
    assert_rule_detected_in_sample('eval_vuln.php.sample', 'SEC-004')


def test_sec_004_no_false_positive_on_comment():
    """Test: eval() dalam komentar TIDAK boleh terdeteksi sebagai RCE"""
    assert_rule_not_detected_in_sample('eval_comment.php.sample', 'SEC-004')


# =========================================================================
# TEST: HARDCODED CREDENTIALS (SEC-001)
# =========================================================================

def test_sec_001_detects_hardcoded_password():
    """Test: Hardcoded password harus terdeteksi"""
    assert_rule_detected_in_sample('hardcoded_cred.php.sample', 'SEC-001')


# =========================================================================
# TEST: CONSOLE LOG (SEC-025)
# =========================================================================

def test_sec_025_detects_console_log():
    """Test: console.log() harus terdeteksi"""
    assert_rule_detected_in_sample('console_log.js.sample', 'SEC-025')


# =========================================================================
# TEST: WEAK CRYPTO (SEC-009)
# =========================================================================

def test_sec_009_detects_md5():
    """Test: md5() harus terdeteksi"""
    assert_rule_detected_in_sample('weak_crypto_md5.php.sample', 'SEC-009')


def test_sec_009_no_false_positive_on_password_hash():
    """Test: password_hash() TIDAK boleh terdeteksi"""
    assert_rule_not_detected_in_sample('weak_crypto_safe.php.sample', 'SEC-009')


# =========================================================================
# TEST: COMMAND INJECTION (SEC-005)
# =========================================================================

def test_sec_005_detects_command_injection():
    """Test: Command injection harus terdeteksi"""
    assert_rule_detected_in_sample('command_injection.php.sample', 'SEC-005')


# =========================================================================
# 🎯 TEMPLATE UNTUK RULE BARU
# =========================================================================
# 
# Saat Anda tambah rule baru (misal SEC-054), ikuti langkah ini:
#
# LANGKAH 1: Buat file sample
#   File: tests/samples/ssrf_vuln.php.sample
#   Isi:
#   <?php
#   $data = file_get_contents($_GET['url']);
#   ?>
#
# LANGKAH 2: Tambahkan test function
#   def test_sec_054_detects_ssrf():
#       assert_rule_detected_in_sample('ssrf_vuln.php.sample', 'SEC-054')
#
# =========================================================================