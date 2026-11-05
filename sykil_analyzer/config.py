"""
SYKIL Configuration Manager
Mengelola konfigurasi dari file .env dengan dukungan cross-platform
"""

import os
import platform
from pathlib import Path
from .logger import get_logger

logger = get_logger("config")

# Nama file .env
ENV_FILE_NAME = ".env"


def get_default_base_dir() -> Path:
    """
    Dapatkan default base directory berdasarkan OS.
    - Windows: C:\Sykil_Security_Analyzer
    - Linux/Mac: ~/.sykil (di home directory user)
    """
    system = platform.system()
    
    if system == "Windows":
        # Windows: C:\Sykil_Security_Analyzer
        return Path("C:/Sykil_Security_Analyzer")
    else:
        # Linux/Mac: ~/.sykil (hidden folder di home directory)
        return Path.home() / ".sykil"


def get_base_dir() -> Path:
    """Dapatkan base directory SYKIL"""
    # Cek environment variable SYKIL_BASE_DIR (prioritas tertinggi)
    env_base = os.environ.get("SYKIL_BASE_DIR")
    if env_base:
        return Path(env_base)
    
    # Cek .env di current working directory
    cwd_env = Path.cwd() / ENV_FILE_NAME
    if cwd_env.exists():
        return get_default_base_dir()
    
    # Cek .env di base directory default
    default_env = get_default_base_dir() / ENV_FILE_NAME
    if default_env.exists():
        return get_default_base_dir()
    
    # Default berdasarkan OS
    return get_default_base_dir()


def ensure_env_file() -> Path:
    """
    Pastikan file .env ada. Jika tidak, buat dengan default values.
    Returns: Path ke file .env
    """
    base_dir = get_base_dir()
    env_path = base_dir / ENV_FILE_NAME
    
    # Buat base directory jika belum ada
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        logger.error(f"Tidak punya izin untuk membuat folder: {base_dir}")
        # Fallback ke current directory
        base_dir = Path.cwd() / ".sykil"
        base_dir.mkdir(parents=True, exist_ok=True)
        env_path = base_dir / ENV_FILE_NAME
    except Exception as e:
        logger.error(f"Error membuat base directory: {e}")
        base_dir = Path.cwd() / ".sykil"
        base_dir.mkdir(parents=True, exist_ok=True)
        env_path = base_dir / ENV_FILE_NAME
    
    # Jika .env belum ada, buat dengan default values
    if not env_path.exists():
        default_content = f"""# ============================================================================
# SYKIL : Security Analyzer - Konfigurasi
# Smashing Vulnerabilities, Securing Code
# ============================================================================
# File ini dibuat otomatis oleh SYKIL.
# Anda bisa mengubah nilai di bawah sesuai kebutuhan.
# Setelah mengubah, jalankan ulang SYKIL untuk menerapkan perubahan.
# ============================================================================

# Base directory untuk semua output SYKIL
SYKIL_BASE_DIR={base_dir.as_posix()}

# Lokasi folder output (laporan JSON/HTML)
SYKIL_OUTPUT_DIR={base_dir.as_posix()}/output

# Lokasi folder backup (sebelum auto-fix)
SYKIL_BACKUP_DIR={base_dir.as_posix()}/backups

# Lokasi folder log
SYKIL_LOG_DIR={base_dir.as_posix()}/logs
"""
        try:
            with open(env_path, 'w', encoding='utf-8') as f:
                f.write(default_content)
            print(f"\n[✓] File konfigurasi dibuat: {env_path}")
            print(f"    Anda bisa mengubah lokasi output/backup/log di file tersebut.\n")
            logger.info(f"Created .env file at: {env_path}")
        except Exception as e:
            logger.error(f"Gagal membuat file .env: {e}")
    
    return env_path


def load_env_file(env_path: Path) -> dict:
    """
    Load file .env dan parse menjadi dictionary
    """
    config = {}
    
    if not env_path.exists():
        return config
    
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip komentar dan baris kosong
                if not line or line.startswith('#'):
                    continue
                # Parse KEY=VALUE
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
    except Exception as e:
        logger.error(f"Error membaca file .env: {e}")
    
    return config


def get_output_dir() -> Path:
    """Dapatkan direktori output"""
    env_path = get_base_dir() / ENV_FILE_NAME
    config = load_env_file(env_path)
    
    output_dir = config.get('SYKIL_OUTPUT_DIR')
    if output_dir:
        path = Path(output_dir)
    else:
        path = get_base_dir() / "output"
    
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_backup_dir() -> Path:
    """Dapatkan direktori backup"""
    env_path = get_base_dir() / ENV_FILE_NAME
    config = load_env_file(env_path)
    
    backup_dir = config.get('SYKIL_BACKUP_DIR')
    if backup_dir:
        path = Path(backup_dir)
    else:
        path = get_base_dir() / "backups"
    
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_log_dir() -> Path:
    """Dapatkan direktori log"""
    env_path = get_base_dir() / ENV_FILE_NAME
    config = load_env_file(env_path)
    
    log_dir = config.get('SYKIL_LOG_DIR')
    if log_dir:
        path = Path(log_dir)
    else:
        path = get_base_dir() / "logs"
    
    path.mkdir(parents=True, exist_ok=True)
    return path


def print_config_info():
    """Tampilkan informasi konfigurasi saat startup"""
    print(f"{'='*70}")
    print(f"📂 Konfigurasi SYKIL")
    print(f"{'='*70}")
    print(f"  OS Detected    : {platform.system()}")
    print(f"  Base Directory : {get_base_dir()}")
    print(f"  Output Dir     : {get_output_dir()}")
    print(f"  Backup Dir     : {get_backup_dir()}")
    print(f"  Log Dir        : {get_log_dir()}")
    print(f"  Config File    : {get_base_dir() / '.env'}")
    print(f"{'='*70}\n")