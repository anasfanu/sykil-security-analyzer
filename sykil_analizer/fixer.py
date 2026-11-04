"""
SYKIL Fixer Module
Auto-fix engine dengan konfirmasi keamanan & undo capability
"""

import os
import re
import json
import shutil
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Callable
from pathlib import Path
from logger import get_logger

logger = get_logger("fixer")


class AutoFixer:
    def __init__(self, backup_dir: str = None):
        # Gunakan backup_dir dari config jika tidak disediakan
        if backup_dir is None:
            try:
                from config import get_backup_dir
                self.backup_dir = str(get_backup_dir())
            except ImportError:
                self.backup_dir = "C:/Sykil_Security_Analyzer/backups"
        else:
            self.backup_dir = backup_dir
        
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Folder untuk menyimpan metadata sesi fix
        self.sessions_dir = os.path.join(self.backup_dir, "sessions")
        os.makedirs(self.sessions_dir, exist_ok=True)
        
        # Session metadata untuk undo
        self.current_session = {
            'session_id': None,
            'timestamp': None,
            'report_file': None,
            'target_dir': None,
            'files': {}  # {original_path: backup_path}
        }
        
        # Registry strategi fix (Level 1 + Level 2)
        self.fix_strategies = {
            # Level 1 - Deterministic Fix
            'SEC-009': self._fix_weak_crypto,
            'SEC-011': self._fix_remove_debug_php,
            'SEC-012': self._fix_insecure_cookie,
            'SEC-019': self._fix_loose_comparison,
            'SEC-020': self._fix_chmod_permission,
            'SEC-022': self._fix_cors_wildcard,
            'SEC-023': self._fix_ssl_verify_false,
            'SEC-024': self._fix_directory_listing,
            'SEC-025': self._fix_remove_console_log,
            'SEC-030': self._fix_http_to_https,
            
            # Level 2 - Context-Aware Fix
            'SEC-003': self._fix_xss_output,
            'SEC-010': self._fix_insecure_random,
            'SEC-013': self._fix_missing_security_headers,
            'SEC-017': self._fix_information_disclosure,
            'SEC-026': self._fix_js_eval,
            'SEC-027': self._fix_innerhtml_xss,
            'SEC-028': self._fix_document_write,
            'SEC-029': self._fix_localstorage_sensitive,
            
            # SEC-001 - Special Logic
            'SEC-001': self._fix_hardcoded_credentials,
            
            # SEC-043 - Unsafe YAML Deserialization
            'SEC-043': self._fix_unsafe_yaml_load,
        }
        
        self.stats = {
            'files_processed': 0,
            'files_fixed': 0,
            'issues_found': 0,
            'issues_fixed': 0,
            'issues_skipped': 0,
            'backups_created': 0,
            'env_file_created': False,
            'credentials_migrated': 0,
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'by_category': {},
            'session_id': None
        }
    
    # =========================================================================
    # KONFIRMASI & PERINGATAN
    # =========================================================================
    
    def _show_warning_and_confirm(self, fixable_count: int, files_count: int, 
                                  target_dir: str) -> bool:
        """
        Tampilkan peringatan keamanan dan minta konfirmasi user.
        Return True jika user konfirmasi Y, False jika N.
        """
        print(f"\n{'='*70}")
        print(f"{'⚠️  PERINGATAN PENTING - AUTO-FIX ENGINE':^70}")
        print(f"{'='*70}")
        print(f"\n📊 Statistik Fix:")
        print(f"   • Files yang akan dimodifikasi : {files_count}")
        print(f"   • Issues yang akan diperbaiki  : {fixable_count}")
        print(f"   • Backup akan dibuat di        : {self.backup_dir}")
        print(f"   • Target folder                : {target_dir}")
        
        print(f"\n⚠️  Risiko yang perlu Anda pahami:")
        print(f"   1. Auto-fix bisa mengubah logika bisnis jika pattern tidak cocok")
        print(f"   2. SELALU test aplikasi setelah fix di environment development")
        print(f"   3. Backup otomatis dibuat, Anda bisa undo kapan saja")
        print(f"   4. Beberapa fix (seperti SEC-003 XSS) mungkin butuh penyesuaian manual")
        print(f"   5. Untuk SEC-001, file .env akan dimodifikasi (credentials ditambahkan)")
        
        print(f"\n💾 Cara Undo (jika terjadi masalah):")
        print(f"   • List sesi fix  : sykil --list-sessions")
        print(f"   • Undo terakhir  : sykil --undo")
        print(f"   • Undo spesifik  : sykil --undo <session_id>")
        
        print(f"\n{'='*70}")
        print(f"Apakah Anda yakin untuk melanjutkan fix?")
        print(f"Pastikan Anda paham apa yang harus dilakukan jika terjadi masalah.")
        
        while True:
            try:
                response = input("Pilih Y jika Anda paham? (Y/N): ").strip().upper()
                if response in ('Y', 'YES'):
                    print(f"\n[✓] Konfirmasi diterima. Memulai auto-fix...\n")
                    return True
                elif response in ('N', 'NO'):
                    print(f"\n[!] Auto-fix dibatalkan oleh user.\n")
                    return False
                else:
                    print("[!] Input tidak valid. Silakan pilih Y atau N.")
            except KeyboardInterrupt:
                print(f"\n\n[!] Auto-fix dibatalkan (Ctrl+C).\n")
                return False
            except EOFError:
                # Non-interactive mode (dipanggil dari script)
                print(f"\n[!] Mode non-interactive, auto-fix dibatalkan untuk keamanan.")
                return False
    
    # =========================================================================
    # SESSION MANAGEMENT (Untuk Undo)
    # =========================================================================
    
    def _init_session(self, report_file: str, target_dir: str):
        """Inisialisasi sesi fix baru"""
        timestamp = datetime.now()
        self.current_session = {
            'session_id': timestamp.strftime("%Y%m%d_%H%M%S"),
            'timestamp': timestamp.isoformat(),
            'report_file': os.path.abspath(report_file),
            'target_dir': os.path.abspath(target_dir),
            'files': {}
        }
        self.stats['session_id'] = self.current_session['session_id']
        logger.info(f"Session initialized: {self.current_session['session_id']}")
    
    def _register_backup(self, original_path: str, backup_path: str):
        """Daftarkan backup ke session metadata"""
        self.current_session['files'][os.path.abspath(original_path)] = os.path.abspath(backup_path)
    
    def _save_session_metadata(self):
        """Simpan metadata sesi ke file JSON"""
        if not self.current_session['files']:
            logger.warning("Tidak ada file yang di-fix, metadata sesi tidak disimpan")
            return
        
        session_file = os.path.join(
            self.sessions_dir,
            f"session_{self.current_session['session_id']}.json"
        )
        
        try:
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(self.current_session, f, indent=2, ensure_ascii=False)
            logger.info(f"Session metadata saved: {session_file}")
        except Exception as e:
            logger.error(f"Gagal menyimpan session metadata: {e}")
    
    @staticmethod
    def list_sessions(backup_dir: str = None) -> List[Dict]:
        """
        List semua sesi fix yang tersedia untuk undo.
        Return list of session metadata.
        """
        if backup_dir is None:
            try:
                from config import get_backup_dir
                backup_dir = str(get_backup_dir())
            except ImportError:
                backup_dir = "C:/Sykil_Security_Analyzer/backups"
        
        sessions_dir = os.path.join(backup_dir, "sessions")
        if not os.path.exists(sessions_dir):
            return []
        
        sessions = []
        for filename in os.listdir(sessions_dir):
            if filename.startswith("session_") and filename.endswith(".json"):
                session_file = os.path.join(sessions_dir, filename)
                try:
                    with open(session_file, 'r', encoding='utf-8') as f:
                        session = json.load(f)
                        sessions.append(session)
                except Exception as e:
                    logger.warning(f"Gagal membaca session file {session_file}: {e}")
        
        # Sort by timestamp descending (terbaru dulu)
        sessions.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return sessions
    
    @staticmethod
    def print_sessions(backup_dir: str = None):
        """Tampilkan daftar sesi fix dalam format user-friendly"""
        sessions = AutoFixer.list_sessions(backup_dir)
        
        if not sessions:
            print("\n[!] Tidak ada sesi fix yang tersedia untuk di-undo.")
            return
        
        print(f"\n{'='*70}")
        print(f"{'📋 DAFTAR SESI FIX YANG TERSEDIA':^70}")
        print(f"{'='*70}\n")
        
        for i, session in enumerate(sessions, 1):
            session_id = session.get('session_id', 'unknown')
            timestamp = session.get('timestamp', 'unknown')
            target_dir = session.get('target_dir', 'unknown')
            files_count = len(session.get('files', {}))
            report_file = session.get('report_file', 'unknown')
            
            print(f"  [{i}] Session ID  : {session_id}")
            print(f"      Waktu       : {timestamp}")
            print(f"      Target      : {target_dir}")
            print(f"      Files       : {files_count} file di-backup")
            print(f"      Report      : {os.path.basename(report_file)}")
            print(f"      Command     : sykil --undo {session_id}")
            print()
        
        print(f"{'='*70}")
        print(f"Gunakan: sykil --undo <session_id> untuk mengembalikan file")
        print(f"{'='*70}\n")
    
    @staticmethod
    def undo_session(session_id: str = None, backup_dir: str = None, 
                    interactive: bool = True) -> Dict:
        """
        Undo sesi fix tertentu.
        Jika session_id None, undo sesi terbaru.
        
        Returns:
            Dict dengan statistik undo
        """
        if backup_dir is None:
            try:
                from config import get_backup_dir
                backup_dir = str(get_backup_dir())
            except ImportError:
                backup_dir = "C:/Sykil_Security_Analyzer/backups"
        
        sessions = AutoFixer.list_sessions(backup_dir)
        
        if not sessions:
            print("\n[!] Tidak ada sesi fix yang tersedia untuk di-undo.")
            return {'success': False, 'error': 'No sessions available'}
        
        # Pilih session
        target_session = None
        if session_id is None:
            # Undo sesi terbaru
            target_session = sessions[0]
            print(f"\n[*] Meng-undo sesi terbaru: {target_session['session_id']}")
        else:
            # Cari session by ID
            for session in sessions:
                if session.get('session_id') == session_id:
                    target_session = session
                    break
            
            if target_session is None:
                print(f"\n[!] Session ID tidak ditemukan: {session_id}")
                return {'success': False, 'error': f'Session {session_id} not found'}
        
        # Konfirmasi undo
        if interactive:
            print(f"\n{'='*70}")
            print(f"{'⚠️  KONFIRMASI UNDO':^70}")
            print(f"{'='*70}")
            print(f"\n📊 Detail Sesi:")
            print(f"   • Session ID  : {target_session['session_id']}")
            print(f"   • Waktu       : {target_session['timestamp']}")
            print(f"   • Target      : {target_session['target_dir']}")
            print(f"   • Files       : {len(target_session['files'])} file akan di-restore")
            print(f"\n⚠️  Peringatan:")
            print(f"   • File asli akan DIGANTI dengan versi backup")
            print(f"   • Perubahan yang Anda buat setelah fix akan HILANG")
            print(f"   • Backup file TIDAK akan dihapus (untuk keamanan)")
            print(f"\n{'='*70}")
            
            try:
                response = input("Lanjutkan undo? (Y/N): ").strip().upper()
                if response not in ('Y', 'YES'):
                    print("\n[!] Undo dibatalkan oleh user.")
                    return {'success': False, 'error': 'User cancelled'}
            except (KeyboardInterrupt, EOFError):
                print("\n[!] Undo dibatalkan.")
                return {'success': False, 'error': 'User cancelled'}
        
        # Lakukan undo
        stats = {
            'session_id': target_session['session_id'],
            'files_restored': 0,
            'files_failed': 0,
            'files_not_found': 0,
            'details': []
        }
        
        print(f"\n[*] Meng-restore {len(target_session['files'])} file...\n")
        
        for original_path, backup_path in target_session['files'].items():
            try:
                if not os.path.exists(backup_path):
                    print(f"  [!] Backup tidak ditemukan: {backup_path}")
                    stats['files_not_found'] += 1
                    stats['details'].append({
                        'file': original_path,
                        'status': 'backup_not_found'
                    })
                    continue
                
                # Restore file
                shutil.copy(backup_path, original_path)
                print(f"  [✓] Restored: {os.path.basename(original_path)}")
                stats['files_restored'] += 1
                stats['details'].append({
                    'file': original_path,
                    'status': 'restored',
                    'backup': backup_path
                })
                
            except Exception as e:
                print(f"  [✗] Gagal restore {os.path.basename(original_path)}: {e}")
                stats['files_failed'] += 1
                stats['details'].append({
                    'file': original_path,
                    'status': 'failed',
                    'error': str(e)
                })
        
        # Hapus session metadata setelah undo berhasil
        if stats['files_restored'] > 0:
            session_file = os.path.join(
                backup_dir, "sessions",
                f"session_{target_session['session_id']}.json"
            )
            try:
                os.remove(session_file)
                logger.info(f"Session metadata removed: {session_file}")
            except Exception as e:
                logger.warning(f"Gagal menghapus session metadata: {e}")
        
        # Print summary
        print(f"\n{'='*70}")
        print(f"{'📊 RINGKASAN UNDO':^70}")
        print(f"{'='*70}")
        print(f"Session ID       : {stats['session_id']}")
        print(f"Files restored   : {stats['files_restored']}")
        print(f"Files failed     : {stats['files_failed']}")
        print(f"Files not found  : {stats['files_not_found']}")
        print(f"{'='*70}\n")
        
        if stats['files_restored'] > 0:
            print("[✓] Undo berhasil! File telah dikembalikan ke kondisi sebelum fix.")
            print("[i] Backup file masih tersimpan di folder backups/ untuk keamanan.\n")
        
        return {'success': True, 'stats': stats}
    
    # =========================================================================
    # MAIN ENTRY POINT
    # =========================================================================
    
    def fix_from_report(self, report_file: str, root_dir: str, 
                       dry_run: bool = False, interactive: bool = False,
                       require_confirmation: bool = True,
                       auto_confirm: bool = False) -> Dict:
        """
        Auto-fix berdasarkan laporan JSON
        
        Args:
            report_file: Path ke file laporan JSON
            root_dir: Direktori root project
            dry_run: Jika True, hanya preview tanpa mengubah file
            interactive: Jika True, minta konfirmasi per issue
            require_confirmation: Jika True, tampilkan peringatan global
            auto_confirm: Jika True, skip konfirmasi (untuk testing/CI)
        
        Returns:
            Dict: Statistik hasil fix
        """
        logger.info(f"Memulai auto-fix dari: {report_file} (dry_run={dry_run})")
        
        # Reset stats
        self.stats = {
            'files_processed': 0, 'files_fixed': 0, 'issues_found': 0,
            'issues_fixed': 0, 'issues_skipped': 0, 'backups_created': 0,
            'env_file_created': False, 'credentials_migrated': 0,
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'by_category': {}, 'dry_run': dry_run, 'session_id': None
        }
        
        # Load report
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report = json.load(f)
        except Exception as e:
            logger.error(f"Gagal membaca report: {e}")
            return self.stats
        
        issues = report.get('issues', [])
        self.stats['issues_found'] = len(issues)
        
        # Filter issues yang bisa di-fix
        fixable_issues = [i for i in issues if i['id'] in self.fix_strategies]
        unfixable_issues = [i for i in issues if i['id'] not in self.fix_strategies]
        
        logger.info(f"Total: {len(issues)}, Fixable: {len(fixable_issues)}, Unfixable: {len(unfixable_issues)}")
        
        if not fixable_issues:
            print("\n[!] Tidak ada masalah yang bisa di-fix otomatis.")
            if unfixable_issues:
                print(f"[i] {len(unfixable_issues)} masalah memerlukan perbaikan manual.")
            return self.stats
        
        # Tampilkan info unfixable issues
        if unfixable_issues:
            print(f"\n{'='*70}\n⚠️  {len(unfixable_issues)} masalah TIDAK BISA di-fix otomatis:\n{'='*70}")
            unfixable_by_id = {}
            for issue in unfixable_issues:
                rule_id = issue['id']
                if rule_id not in unfixable_by_id:
                    unfixable_by_id[rule_id] = {'kategori': issue['kategori'], 'count': 0, 'severity': issue['severity']}
                unfixable_by_id[rule_id]['count'] += 1
            
            for rule_id, info in unfixable_by_id.items():
                print(f"  [{info['severity']}] {rule_id} - {info['kategori']} ({info['count']}x)")
            print(f"{'='*70}\n")
        
        # Konfirmasi global (jika bukan dry-run)
        if not dry_run and require_confirmation and not auto_confirm:
            files_to_fix = len(set(i['file'] for i in fixable_issues))
            if not self._show_warning_and_confirm(len(fixable_issues), files_to_fix, root_dir):
                return self.stats
        
        # Initialize session (untuk undo)
        if not dry_run:
            self._init_session(report_file, root_dir)
        
        # Group fixable issues by file
        issues_by_file = {}
        for issue in fixable_issues:
            file = issue['file']
            if file not in issues_by_file:
                issues_by_file[file] = []
            issues_by_file[file].append(issue)
        
        # Process each file
        for file, file_issues in issues_by_file.items():
            file_path = os.path.join(root_dir, file)
            self._process_file(file_path, file_issues, dry_run, interactive, root_dir)
        
        # Save session metadata (untuk undo)
        if not dry_run and self.current_session['files']:
            self._save_session_metadata()
            print(f"\n💾 Session ID: {self.current_session['session_id']}")
            print(f"   Gunakan 'sykil --undo {self.current_session['session_id']}' untuk mengembalikan file.")
        
        return self.stats
    
    # =========================================================================
    # FILE PROCESSING
    # =========================================================================
    
    def _process_file(self, file_path: str, issues: List[Dict], dry_run: bool, 
                     interactive: bool, root_dir: str):
        """Proses satu file dengan semua issues-nya"""
        self.stats['files_processed'] += 1
        
        if not os.path.exists(file_path):
            logger.warning(f"File tidak ditemukan: {file_path}")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            fixes_applied = []
            issues_sorted = sorted(issues, key=lambda x: x['line'], reverse=True)
            
            for issue in issues_sorted:
                line_idx = issue['line'] - 1
                
                if line_idx < 0 or line_idx >= len(lines):
                    logger.warning(f"Line number out of range: {issue['line']} di {file_path}")
                    self.stats['issues_skipped'] += 1
                    continue
                
                # Interactive mode
                if interactive:
                    print(f"\n[?] Fix issue ini?")
                    print(f"    File: {file_path}:{issue['line']}")
                    print(f"    Rule: {issue['id']} - {issue['kategori']}")
                    print(f"    Code: {issue['content'][:80]}")
                    try:
                        response = input("    [y/N]: ").strip().lower()
                        if response != 'y':
                            self.stats['issues_skipped'] += 1
                            continue
                    except (KeyboardInterrupt, EOFError):
                        print("\n[!] Interactive mode dibatalkan.")
                        break
                
                # Ambil fungsi fix yang sesuai
                fix_func = self.fix_strategies.get(issue['id'])
                if fix_func:
                    # Special handling untuk SEC-001 (butuh root_dir untuk .env)
                    if issue['id'] == 'SEC-001':
                        result = fix_func(lines, line_idx, issue, root_dir, dry_run)
                    else:
                        result = fix_func(lines, line_idx, issue)
                    
                    if result.get('fixed'):
                        fixes_applied.append({
                            'line': issue['line'],
                            'rule_id': issue['id'],
                            'kategori': issue['kategori'],
                            'description': result.get('description', 'Fixed')
                        })
                        self.stats['issues_fixed'] += 1
                        
                        # Update severity stats
                        severity = issue['severity']
                        self.stats['by_severity'][severity] = self.stats['by_severity'].get(severity, 0) + 1
                        
                        # Update category stats
                        kategori = issue['kategori']
                        self.stats['by_category'][kategori] = self.stats['by_category'].get(kategori, 0) + 1
                        
                        # Track SEC-001 special stats
                        if issue['id'] == 'SEC-001':
                            if result.get('env_created'):
                                self.stats['env_file_created'] = True
                            self.stats['credentials_migrated'] += result.get('migrated_count', 0)
                    else:
                        self.stats['issues_skipped'] += 1
                        if result.get('reason'):
                            logger.debug(f"Fix skipped: {result['reason']}")
            
            if fixes_applied:
                new_content = ''.join(lines)
                
                if dry_run:
                    print(f"\n[DRY-RUN] Akan fix {len(fixes_applied)} issue di: {file_path}")
                    for fix in fixes_applied:
                        print(f"  • Baris {fix['line']}: [{fix['rule_id']}] {fix['description']}")
                else:
                    # Create backup DAN daftarkan ke session
                    backup_path = self._create_backup(file_path)
                    self._register_backup(file_path, backup_path)
                    self.stats['backups_created'] += 1
                    
                    # Write new content
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    
                    self.stats['files_fixed'] += 1
                    print(f"\n[✓] Fixed {len(fixes_applied)} issue di: {file_path}")
                    for fix in fixes_applied:
                        print(f"  • Baris {fix['line']}: [{fix['rule_id']}] {fix['description']}")
                    print(f"  💾 Backup: {backup_path}")
        
        except Exception as e:
            logger.exception(f"Error processing {file_path}: {e}")
    
    # =========================================================================
    # LEVEL 1 - DETERMINISTIC FIX
    # =========================================================================
    
    def _fix_weak_crypto(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        pattern = r'\b(md5|sha1)\s*\(\s*([^)]+)\)'
        def replace_func(match):
            return f"password_hash({match.group(2).strip()}, PASSWORD_BCRYPT)"
        new_line = re.sub(pattern, replace_func, line, flags=re.IGNORECASE)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Ganti md5/sha1() dengan password_hash()'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_remove_debug_php(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx].strip()
        debug_pattern = r'^\s*(var_dump|print_r|debug_print_backtrace|dd)\s*\(.*?\)\s*;?\s*$'
        if re.match(debug_pattern, line, re.IGNORECASE):
            lines[line_idx] = ''
            return {'fixed': True, 'description': 'Hapus baris debug function'}
        
        line_content = lines[line_idx]
        new_line = re.sub(r'\b(var_dump|print_r|debug_print_backtrace|dd)\s*\([^;]*\)\s*;?', '', line_content, flags=re.IGNORECASE)
        if new_line != line_content:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Hapus debug function dari baris'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_insecure_cookie(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        if re.search(r'(secure|httponly|samesite)', line, re.IGNORECASE):
            return {'fixed': False, 'reason': 'Sudah ada flag keamanan'}
        if 'setcookie(' in line and line.rstrip().endswith(');'):
            lines[line_idx] = line.rstrip()[:-2] + ', ["secure" => true, "httponly" => true, "samesite" => "Strict"]); // Auto-fixed\n'
            return {'fixed': True, 'description': 'Tambahkan flag keamanan ke cookie'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_loose_comparison(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        pattern = r'(\$\w+(?:->\w+)?)\s*==\s*([\'"]{2})'
        new_line = re.sub(pattern, r'\1 === \2', line)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Ganti == dengan === (strict comparison)'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_chmod_permission(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        pattern = r'(chmod\s*\([^,]+,\s*)0?(777)(\s*\))'
        def replace_func(match):
            return f"{match.group(1)}0755{match.group(3)}"
        new_line = re.sub(pattern, replace_func, line, flags=re.IGNORECASE)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Ganti permission 777 dengan 755'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_cors_wildcard(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        pattern = r'(Access-Control-Allow-Origin\s*:\s*)\*'
        new_line = re.sub(pattern, r'\1https://yourdomain.com // TODO: Ganti dengan domain yang diizinkan', line, flags=re.IGNORECASE)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Ganti wildcard CORS dengan domain spesifik'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_ssl_verify_false(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        new_line = re.sub(r'(CURLOPT_SSL_VERIFYPEER\s*(?:=>|:)\s*)false', r'\1true', line, flags=re.IGNORECASE)
        new_line = re.sub(r'(verify\s*=\s*)False', r'\1True', new_line, flags=re.IGNORECASE)
        new_line = re.sub(r'(verify\s*=\s*)false', r'\1true', new_line, flags=re.IGNORECASE)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Aktifkan SSL verification'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_directory_listing(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        pattern = r'(Options\s+)\+Indexes'
        new_line = re.sub(pattern, r'\1-Indexes', line, flags=re.IGNORECASE)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Disable directory listing (+Indexes → -Indexes)'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_remove_console_log(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx].strip()
        console_pattern = r'^\s*console\.(log|debug|info|warn|error)\s*\(.*?\)\s*;?\s*$'
        if re.match(console_pattern, line, re.IGNORECASE):
            lines[line_idx] = ''
            return {'fixed': True, 'description': 'Hapus baris console.log()'}
        
        line_content = lines[line_idx]
        new_line = re.sub(r'console\.(log|debug|info|warn|error)\s*\([^;]*\)\s*;?', '', line_content, flags=re.IGNORECASE)
        if new_line != line_content:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Hapus console.log() dari baris'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_http_to_https(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        pattern = r'(https?://)(?!localhost|127\.0\.0\.1|0\.0\.0\.0)'
        def replace_func(match):
            return 'https://' if match.group(1) == 'http://' else match.group(1)
        new_line = re.sub(pattern, replace_func, line)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Ganti http:// dengan https://'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    # =========================================================================
    # LEVEL 2 - CONTEXT-AWARE FIX
    # =========================================================================
    
    def _fix_xss_output(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        if re.search(r'(htmlspecialchars|e\(|clean\(|sanitize)', line, re.IGNORECASE):
            return {'fixed': False, 'reason': 'Sudah ada sanitasi'}
        
        start_idx = max(0, line_idx - 3)
        context = ''.join(lines[start_idx:line_idx + 1])
        if re.search(r'(htmlspecialchars|e\(|clean\(|sanitize)', context, re.IGNORECASE):
            return {'fixed': False, 'reason': 'Variabel sudah di-sanitize di baris sebelumnya'}
        
        pattern = r'(echo\s+)(\$[\w\->]+)(\s*;)'
        def replace_func(match):
            return f"{match.group(1)}htmlspecialchars({match.group(2)}, ENT_QUOTES, 'UTF-8'){match.group(3)}"
        
        new_line = re.sub(pattern, replace_func, line, flags=re.IGNORECASE)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Wrap output dengan htmlspecialchars()'}
        return {'fixed': False, 'reason': 'Pattern echo tidak cocok'}
    
    def _fix_insecure_random(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        pattern = r'\b(rand|mt_rand)\s*\(\s*([^,]+),\s*([^)]+)\)'
        def replace_func(match):
            return f"random_int({match.group(2).strip()}, {match.group(3).strip()})"
        new_line = re.sub(pattern, replace_func, line, flags=re.IGNORECASE)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Ganti rand()/mt_rand() dengan random_int()'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_missing_security_headers(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        if '<?php' in ''.join(lines[:line_idx + 1]):
            full_content = ''.join(lines)
            if 'X-Frame-Options' in full_content:
                return {'fixed': False, 'reason': 'Security headers sudah ada'}
            if '<?php' in line:
                header_block = """
// Security Headers - Auto-added
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
"""
                lines.insert(line_idx + 1, header_block)
                return {'fixed': True, 'description': 'Inject security headers'}
        return {'fixed': False, 'reason': 'Bukan di awal file PHP'}
    
    def _fix_information_disclosure(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        pattern = r'(display_errors\s*=\s*)(1|On|true)'
        def replace_func(match):
            return f"{match.group(1)}0 // Auto-fixed: disabled for production"
        new_line = re.sub(pattern, replace_func, line, flags=re.IGNORECASE)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Disable display_errors'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_js_eval(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        if 'eval(' in line and not line.strip().startswith('//'):
            lines[line_idx] = f"// TODO: SECURITY - eval() removed. Refactor this logic.\n// {line}"
            return {'fixed': True, 'description': 'Comment out eval() dengan TODO marker'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_innerhtml_xss(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        pattern = r'(\w+)\.innerHTML\s*=\s*(\$\w+|\w+)\s*;'
        def replace_func(match):
            return f"{match.group(1)}.textContent = {match.group(2)}; // Auto-fixed: innerHTML → textContent"
        new_line = re.sub(pattern, replace_func, line, flags=re.IGNORECASE)
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Convert innerHTML ke textContent'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok atau terlalu kompleks'}
    
    def _fix_document_write(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        if 'document.write(' in line and not line.strip().startswith('//'):
            lines[line_idx] = f"// TODO: SECURITY - document.write() removed. Use DOM manipulation.\n// {line}"
            return {'fixed': True, 'description': 'Comment out document.write() dengan TODO'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    def _fix_localstorage_sensitive(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        line = lines[line_idx]
        pattern = r'localStorage\.setItem\s*\(\s*[\'"](token|password|secret|key)[\'"]'
        if re.search(pattern, line, re.IGNORECASE) and not line.strip().startswith('//'):
            lines[line_idx] = f"// TODO: SECURITY - Migrate to httpOnly cookie\n// {line}"
            return {'fixed': True, 'description': 'Comment out localStorage sensitive data'}
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    # =========================================================================
    # SEC-001 - SPECIAL LOGIC
    # =========================================================================
    
    def _fix_hardcoded_credentials(self, lines: List[str], line_idx: int, 
                                   issue: Dict, root_dir: str, dry_run: bool) -> Dict:
        line = lines[line_idx]
        pattern = r'(\$\w+)\s*=\s*[\'"]([^\'"]{4,})[\'"]\s*;'
        
        match = re.search(pattern, line, re.IGNORECASE)
        if not match:
            return {'fixed': False, 'reason': 'Pattern credential tidak cocok'}
        
        var_name = match.group(1)
        cred_value = match.group(2)
        env_var_name = var_name.lstrip('$').upper()
        
        env_file_path = os.path.join(root_dir, '.env')
        
        if not os.path.exists(env_file_path):
            return {
                'fixed': False,
                'reason': (
                    f"File .env tidak ditemukan di '{root_dir}'. "
                    f"Buat file '.env' secara manual di folder tersebut, "
                    f"tambahkan baris '{env_var_name}={cred_value}', "
                    f"lalu jalankan auto-fix kembali."
                )
            }
        
        with open(env_file_path, 'r', encoding='utf-8') as f:
            env_content = f.read()
        
        if f"{env_var_name}=" not in env_content:
            if not dry_run:
                source_file = issue.get('file', 'unknown_file')
                source_line = issue.get('line', 'unknown_line')
                with open(env_file_path, 'a', encoding='utf-8') as f:
                    f.write(f"\n# Dipindahkan dari {source_file} baris {source_line} oleh SYKIL Security Analyzer\n")
                    f.write(f"{env_var_name}={cred_value}\n")
                logger.info(f"Appended {env_var_name} to .env (from {source_file}:{source_line})")
        
        new_line = re.sub(
            pattern,
            lambda m: f"{m.group(1)} = getenv('{env_var_name}') ?: '{m.group(2)}'; // Migrated by SYKIL",
            line,
            flags=re.IGNORECASE
        )
        
        if new_line != line:
            lines[line_idx] = new_line
            return {
                'fixed': True,
                'description': f'Migrate {var_name} ke .env ({env_var_name})',
                'env_created': False,
                'migrated_count': 1
            }
        
        return {'fixed': False, 'reason': 'Gagal replace credential di kode'}
    
    # =========================================================================
    # SEC-043 - UNSAFE YAML DESERIALIZATION
    # =========================================================================
    
    def _fix_unsafe_yaml_load(self, lines: List[str], line_idx: int, issue: Dict) -> Dict:
        """SEC-043: Ganti yaml.load() dengan yaml.safe_load()"""
        line = lines[line_idx]
        
        if re.search(r'yaml\.safe_load', line, re.IGNORECASE):
            return {'fixed': False, 'reason': 'Sudah menggunakan yaml.safe_load()'}
        
        if re.search(r'Loader\s*=\s*(yaml\.)?(Safe|CSafe)Loader', line):
            return {'fixed': False, 'reason': 'Sudah menggunakan SafeLoader/CSafeLoader'}
        
        new_line = re.sub(r'\byaml\.load\s*\(', 'yaml.safe_load(', line, flags=re.IGNORECASE)
        new_line = re.sub(r',\s*Loader\s*=\s*[^,)]+', '', new_line, flags=re.IGNORECASE)
        new_line = re.sub(
            r'(yaml\.safe_load\s*\()\s+(.*?)\s+(\))',
            r'\1\2\3',
            new_line,
            flags=re.IGNORECASE
        )
        
        if new_line != line:
            lines[line_idx] = new_line
            return {'fixed': True, 'description': 'Ganti yaml.load() dengan yaml.safe_load()'}
        
        return {'fixed': False, 'reason': 'Pattern tidak cocok'}
    
    # =========================================================================
    # BACKUP MANAGEMENT
    # =========================================================================
    
    def _create_backup(self, file_path: str) -> str:
        """Buat backup file dengan timestamp di folder terpusat"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.basename(file_path)
        date_folder = datetime.now().strftime("%Y-%m-%d")
        backup_subdir = Path(self.backup_dir) / date_folder
        backup_subdir.mkdir(parents=True, exist_ok=True)
        
        backup_name = f"{filename}.{timestamp}.bak"
        backup_path = backup_subdir / backup_name
        
        shutil.copy(file_path, backup_path)
        logger.info(f"Backup created: {backup_path}")
        return str(backup_path)
    
    # =========================================================================
    # STATISTICS & REPORTING
    # =========================================================================
    
    def print_summary(self):
        print(f"\n{'='*70}\n{'RINGKASAN AUTO-FIX':^70}\n{'='*70}")
        print(f"Files diproses       : {self.stats['files_processed']}")
        print(f"Files diperbaiki     : {self.stats['files_fixed']}")
        print(f"Issues ditemukan     : {self.stats['issues_found']}")
        print(f"Issues diperbaiki    : {self.stats['issues_fixed']}")
        print(f"Issues dilewati      : {self.stats['issues_skipped']}")
        print(f"Backups dibuat       : {self.stats['backups_created']}")
        
        if self.stats.get('session_id'):
            print(f"Session ID           : {self.stats['session_id']}")
        
        if self.stats['env_file_created']:
            print(f"\n🔐 File .env BARU telah dibuat!")
            print(f"   ⚠️  PENTING: Pastikan .env ada di .gitignore!")
        if self.stats['credentials_migrated'] > 0:
            print(f"   Credentials migrated: {self.stats['credentials_migrated']}")
        
        if self.stats.get('dry_run'):
            print(f"\n⚠️  MODE DRY-RUN: Tidak ada file yang benar-benar diubah!")
        
        if self.stats['by_severity']:
            print(f"\nBerdasarkan Severity:")
            for severity, count in self.stats['by_severity'].items():
                if count > 0: print(f"  {severity:10s}: {count}")
        
        if self.stats['by_category']:
            print(f"\nBerdasarkan Kategori:")
            for kategori, count in sorted(self.stats['by_category'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {kategori[:40]:40s}: {count}")
        
        print(f"{'='*70}")
    
    def export_stats(self, output_file: str = None):
        if output_file is None:
            try:
                from config import get_output_dir
                output_file = str(get_output_dir() / "fix_stats.json")
            except ImportError:
                output_file = "C:/Sykil_Security_Analyzer/output/fix_stats.json"
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, indent=2, ensure_ascii=False)
        logger.info(f"Statistik fix disimpan: {output_file}")
        return output_file