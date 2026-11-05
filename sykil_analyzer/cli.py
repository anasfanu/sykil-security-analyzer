"""
SYKIL : Security Analyzer

CLI Entry Point
"""

import argparse
import sys
import os
import json
from .scanner import SecurityScanner
from .reporter import Reporter
from .fixer import AutoFixer
from .logger import setup_logger, get_logger, setup_global_exception_handler, view_logs
from .config import ensure_env_file, print_config_info

# Setup global exception handler
setup_global_exception_handler()

# Pastikan file .env ada (auto-create jika belum ada)
ensure_env_file()

# Setup logger untuk SYKIL
logger = setup_logger()


def main():
    parser = argparse.ArgumentParser(
        prog="sykil",
        description="🔒 SYKIL : Security Analyzer - Smashing Vulnerabilities, Securing Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════════╗
║          SYKIL : Security Analyzer v1.0.0                    ║
╚══════════════════════════════════════════════════════════════╝
Contoh penggunaan:
  sykil /path/to/project
  sykil /path/to/project --export json
  sykil /path/to/project --export html
  sykil /path/to/project --export both
  sykil --fix output/sykil_report_20261027_120000.json
  sykil --fix output/sykil_report.json --dry-run
  sykil --fix output/sykil_report.json --interactive
  sykil --fix output/sykil_report.json --yes
  sykil --fix output/sykil_report.json --export-stats
  sykil --list-sessions
  sykil --undo
  sykil --undo 20261104_213000
  sykil --view-logs app
  sykil --view-logs error
        """
    )
    
    parser.add_argument("target_dir", nargs="?", default=".", 
                       help="Direktori target (default: current directory)")
    
    parser.add_argument("--export", choices=['json', 'html', 'both'], 
                       help="Export laporan ke format tertentu")
    
    parser.add_argument("--fix", metavar="REPORT_FILE", 
                       help="Auto-fix berdasarkan laporan JSON")
    
    parser.add_argument("--dry-run", action="store_true",
                       help="Preview fix tanpa mengubah file (aman)")
    
    parser.add_argument("--interactive", "-i", action="store_true",
                       help="Konfirmasi setiap fix secara manual")
    
    parser.add_argument("--yes", "-y", action="store_true",
                       help="Skip konfirmasi keamanan (untuk CI/CD atau scripting)")
    
    parser.add_argument("--export-stats", action="store_true",
                       help="Export statistik fix ke JSON")
    
    parser.add_argument("--list-sessions", action="store_true",
                       help="List semua sesi fix yang tersedia untuk undo")
    
    parser.add_argument("--undo", nargs="?", const="latest", metavar="SESSION_ID",
                       help="Undo sesi fix (default: sesi terbaru)")
    
    parser.add_argument("--view-logs", metavar="LOG_TYPE",
                       help="Lihat log (app/error)")
    
    parser.add_argument("--log-lines", type=int, default=50,
                       help="Jumlah baris log yang ditampilkan (default: 50)")
    
    parser.add_argument("--version", action="version",
                       version="SYKIL : Security Analyzer v1.0.0")
    
    args = parser.parse_args()
    
    # =========================================================================
    # Mode: List Sessions
    # =========================================================================
    if args.list_sessions:
        AutoFixer.print_sessions()
        sys.exit(0)
    
    # =========================================================================
    # Mode: Undo
    # =========================================================================
    if args.undo is not None:
        try:
            session_id = None if args.undo == "latest" else args.undo
            
            if session_id:
                logger.info(f"Undo session: {session_id}")
            else:
                logger.info("Undo latest session")
            
            result = AutoFixer.undo_session(session_id=session_id, interactive=True)
            
            if result.get('success'):
                sys.exit(0)
            else:
                sys.exit(1)
        
        except KeyboardInterrupt:
            print("\n[!] Undo dibatalkan oleh user.")
            sys.exit(130)
        except Exception as e:
            logger.exception(f"Gagal melakukan undo: {e}")
            print(f"\n[!] Error: {e}")
            sys.exit(1)
    
    # =========================================================================
    # Mode: Lihat Log
    # =========================================================================
    if args.view_logs:
        view_logs(args.view_logs, args.log_lines)
        sys.exit(0)
    
    # =========================================================================
    # Mode: Auto-Fix
    # =========================================================================
    if args.fix:
        try:
            if not os.path.exists(args.fix):
                logger.error(f"File laporan tidak ditemukan: {args.fix}")
                print(f"\n[!] Error: File laporan tidak ditemukan: {args.fix}")
                sys.exit(1)
            
            with open(args.fix, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            fix_target_dir = report_data.get('target_dir', '.')
            all_issues = report_data.get('issues', [])
            
            print(f"\n{'='*70}")
            print(f"🔒 SYKIL : Security Analyzer - AUTO-FIX ENGINE")
            print(f"   Smashing Vulnerabilities, Securing Code")
            print(f"{'='*70}")
            print(f"[*] Laporan    : {args.fix}")
            print(f"[*] Target     : {fix_target_dir}")
            print(f"[*] Mode       : {'DRY-RUN (Preview)' if args.dry_run else 'LIVE (Akan mengubah file)'}")
            print(f"[*] Interactive: {'Ya' if args.interactive else 'Tidak'}")
            print(f"[*] Auto-confirm: {'Ya' if args.yes else 'Tidak'}")
            print(f"{'='*70}\n")
            
            print_config_info()
            
            logger.info(f"Memulai Auto-Fix untuk folder: {fix_target_dir}")
            
            fixer = AutoFixer()
            stats = fixer.fix_from_report(
                args.fix, 
                fix_target_dir,
                dry_run=args.dry_run,
                interactive=args.interactive,
                require_confirmation=not args.dry_run,
                auto_confirm=args.yes
            )
            
            fixer.print_summary()
            
            if all_issues:
                Reporter.display_manual_fixes(all_issues)
            
            if args.export_stats:
                stats_file = fixer.export_stats()
                print(f"\n[✓] Statistik fix disimpan: {stats_file}")
            
            logger.info(f"Auto-Fix selesai: {stats}")
            sys.exit(0)
            
        except KeyboardInterrupt:
            logger.warning("Auto-fix dibatalkan oleh user")
            print("\n[!] Auto-fix dibatalkan.")
            sys.exit(130)
        except Exception as e:
            logger.exception(f"Gagal melakukan auto-fix: {e}")
            print(f"\n[!] Error: {e}")
            sys.exit(1)
    
    # =========================================================================
    # Mode: Scan
    # =========================================================================
    try:
        target_dir = os.path.abspath(args.target_dir)
        
        if not os.path.isdir(target_dir):
            logger.error(f"Direktori tidak ditemukan: {target_dir}")
            print(f"\n[!] Error: Direktori tidak ditemukan: {target_dir}")
            sys.exit(1)
        
        logger.info(f"Memulai scan di: {target_dir}")
        
        print(f"\n{'='*70}")
        print(f"🔒 SYKIL : Security Analyzer")
        print(f"   Smashing Vulnerabilities, Securing Code")
        print(f"{'='*70}")
        print(f"[*] Target: {target_dir}")
        print(f"{'='*70}\n")
        
        print_config_info()
        
        scanner = SecurityScanner()
        
        def progress_callback(file_count, current_file):
            print(f"\r[*] Scanning... File #{file_count}: {current_file[:50]}{'...' if len(current_file) > 50 else ''}", 
                  end='', flush=True)
        
        issues, total_files = scanner.scan_directory(target_dir, progress_callback)
        print("\n")
        
        Reporter.console_report(issues, total_files)
        Reporter.display_manual_fixes(issues)
        
        if args.export:
            if args.export in ['json', 'both']:
                Reporter.export_json(issues, total_files, target_dir)
            if args.export in ['html', 'both']:
                Reporter.export_html(issues, total_files)
        
        critical_count = sum(1 for i in issues if i['severity'] == 'CRITICAL')
        logger.info(f"Scan selesai. Files: {total_files}, Issues: {len(issues)}, Critical: {critical_count}")
        
        if critical_count > 0:
            logger.warning(f"Ditemukan {critical_count} celah CRITICAL!")
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.warning("Scan dibatalkan oleh user")
        print("\n[!] Scan dibatalkan.")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Error tidak terduga saat scan: {e}")
        print(f"\n[!] Error: {e}")
        sys.exit(1)