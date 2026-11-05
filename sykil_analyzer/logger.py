"""
SYKIL Logger Module
Sistem logging terpusat dengan konfigurasi dari .env
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Import config (akan di-load nanti setelah config.py siap)
# Untuk menghindari circular import, kita load lazy


# ANSI Colors untuk console
class ColorFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[94m',
        'INFO': '\033[92m',
        'WARNING': '\033[93m',
        'ERROR': '\033[91m',
        'CRITICAL': '\033[95m',
    }
    RESET = '\033[0m'
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def _get_log_dir():
    """Lazy load log directory dari config"""
    try:
        from config import get_log_dir
        return get_log_dir()
    except ImportError:
        # Fallback jika config belum ada
        return Path("C:/Sykil_Security_Analyzer/logs")


# Logger name untuk SYKIL
LOGGER_NAME = "sykil"


def setup_logger(name=LOGGER_NAME, log_level=logging.INFO):
    """
    Setup logger terpusat untuk SYKIL dengan:
    - Console handler (berwarna)
    - File handler (semua log, rotasi 5MB x 5 file)
    - Error handler (hanya ERROR & CRITICAL)
    """
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Hindari duplicate handler
    if logger.handlers:
        return logger
    
    # Format untuk file log
    file_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(filename)s:%(lineno)d | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Format untuk console (berwarna)
    console_formatter = ColorFormatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # =========================================================================
    # 1. Console Handler
    # =========================================================================
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # =========================================================================
    # 2. File Handler - sykil.log (semua log)
    # =========================================================================
    log_dir = _get_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    
    app_log_path = log_dir / "sykil.log"
    app_handler = RotatingFileHandler(
        app_log_path,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=5,
        encoding='utf-8'
    )
    app_handler.setLevel(logging.INFO)
    app_handler.setFormatter(file_formatter)
    logger.addHandler(app_handler)
    
    # =========================================================================
    # 3. File Handler - sykil_error.log (hanya ERROR & CRITICAL)
    # =========================================================================
    error_log_path = log_dir / "sykil_error.log"
    error_handler = RotatingFileHandler(
        error_log_path,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)
    logger.addHandler(error_handler)
    
    return logger


def get_logger(name=None):
    """Ambil logger yang sudah di-setup"""
    if name:
        return logging.getLogger(f"{LOGGER_NAME}.{name}")
    return logging.getLogger(LOGGER_NAME)


def log_exception(logger, message="Exception occurred"):
    """Log exception lengkap dengan stack trace"""
    logger.exception(message)


# =============================================================================
# Global Exception Handler
# =============================================================================
def global_exception_handler(exc_type, exc_value, exc_traceback):
    """Handler untuk uncaught exceptions"""
    logger = get_logger()
    
    if issubclass(exc_type, KeyboardInterrupt):
        logger.warning("SYKIL dihentikan oleh user (Ctrl+C)")
        return
    
    logger.critical(
        f"UNCAUGHT EXCEPTION: {exc_type.__name__}",
        exc_info=(exc_type, exc_value, exc_traceback)
    )


def setup_global_exception_handler():
    """Pasang global exception handler"""
    sys.excepthook = global_exception_handler


# =============================================================================
# Utility: Lihat isi log
# =============================================================================
def view_logs(log_type="app", lines=50):
    """Lihat isi log terakhir"""
    log_file_map = {
        'app': 'sykil.log',
        'error': 'sykil_error.log'
    }
    
    log_filename = log_file_map.get(log_type, 'sykil.log')
    log_dir = _get_log_dir()
    log_file = log_dir / log_filename
    
    if not log_file.exists():
        print(f"[!] File log tidak ditemukan: {log_file}")
        return
    
    print(f"\n{'='*70}")
    print(f"📄 SYKIL LOG: {log_file} (terakhir {lines} baris)")
    print(f"{'='*70}\n")
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            log_lines = f.readlines()
            for line in log_lines[-lines:]:
                print(line.rstrip())
    except Exception as e:
        print(f"[!] Error membaca log: {e}")