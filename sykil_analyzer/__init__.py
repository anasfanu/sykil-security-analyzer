"""
SYKIL : Security Analyzer

Advanced SAST (Static Application Security Testing) tool
dengan kemampuan auto-fix untuk 25+ jenis kerentanan.
"""

__version__ = "1.0.0"
__author__ = "anasfanu"
__license__ = "MIT"

from .scanner import SecurityScanner
from .reporter import Reporter
from .fixer import AutoFixer

__all__ = ["SecurityScanner", "Reporter", "AutoFixer"]