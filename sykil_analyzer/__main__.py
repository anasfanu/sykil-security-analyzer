"""
Entry point untuk menjalankan SYKIL sebagai module:
    python -m sykil_analyzer /path/to/project
"""

from .cli import main

if __name__ == "__main__":
    main()