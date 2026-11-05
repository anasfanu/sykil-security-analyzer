"""
SYKIL Scanner Module
Mesin pemindai keamanan dengan deteksi string literal & docstring
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Tuple, Callable, Optional
from .logger import get_logger


# Helper untuk akses file data dari dalam package
def _get_data_path(filename: str) -> Path:
    """Dapatkan path absolut ke file data dalam package"""
    return Path(__file__).parent / 'data' / filename

logger = get_logger("scanner")


class SecurityScanner:
    def __init__(self, rules_file: str = None):
        """Initialize scanner dengan rules dari JSON"""
        if rules_file is None:
            # Cari rules.json di beberapa lokasi (prioritas)
            possible_paths = [
                Path("rules.json"),                                    # CWD
                Path("C:/Sykil_Security_Analyzer/rules.json"),         # Base dir
                _get_data_path("rules.json"),                          # Dalam package ⭐
            ]
            
            for path in possible_paths:
                if path.exists():
                    rules_file = str(path)
                    break
            
            if rules_file is None:
                # Fallback ke path dalam package
                rules_file = str(_get_data_path("rules.json"))
        
        logger.debug(f"Initializing scanner with rules: {rules_file}")
        self.rules = self._load_rules(rules_file)
        
        # Konfigurasi folder yang diabaikan
        self.ignored_dirs = {
            '.git', 'vendor', 'node_modules', 'storage', 'tests', '__pycache__',
            '.idea', '.vscode', 'venv', 'env', '.venv', 'virtualenv', 'pipenv',
            'site-packages', '.next', 'dist', 'build', 'output', 'logs', 'backups',
            'uploads', 'Sykil_Security_Analyzer'
        }
        
        self.ignored_files = {
            'security_analyzer.py', 'deep_project_analyzer.py',
            '.env', '.env.example', 'package-lock.json'
        }
        
        self.allowed_extensions = {
            '.php', '.js', '.py', '.html', '.twig', '.blade.php',
            '.java', '.rb', '.jsx', '.tsx', '.vue'
        }
    
    def _load_rules(self, rules_file: str) -> List[Dict]:
        """Load dan compile aturan dari JSON"""
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                rules = data.get('rules', [])
                
                for rule in rules:
                    rule['compiled_pattern'] = re.compile(rule['pattern'])
                
                logger.info(f"Berhasil load {len(rules)} rules")
                return rules
        except FileNotFoundError:
            logger.error(f"File rules tidak ditemukan: {rules_file}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON di {rules_file}: {e}")
            return []
        except Exception as e:
            logger.exception(f"Gagal load rules dari {rules_file}: {e}")
            return []
    
    def _is_in_docstring(self, lines: List[str], line_idx: int) -> bool:
        '''
        Cek apakah baris tertentu berada di dalam docstring Python.
        Mendeteksi docstring multi-line DAN single-line.
        '''
        # Buat triple quote dengan chr() untuk menghindari ambiguity
        TRIPLE_DOUBLE = chr(34) * 3
        TRIPLE_SINGLE = chr(39) * 3
        
        # Cek apakah baris target itu sendiri adalah docstring single-line
        target_line = lines[line_idx].strip()
        if (target_line.startswith(TRIPLE_DOUBLE) and target_line.endswith(TRIPLE_DOUBLE) and 
            target_line.count(TRIPLE_DOUBLE) == 2):
            return True
        if (target_line.startswith(TRIPLE_SINGLE) and target_line.endswith(TRIPLE_SINGLE) and 
            target_line.count(TRIPLE_SINGLE) == 2):
            return True
        
        # Track state untuk docstring multi-line
        in_docstring = False
        docstring_char = None
        
        for i in range(line_idx):
            line = lines[i]
            j = 0
            
            while j < len(line):
                if j + 2 < len(line):
                    triple = line[j:j+3]
                    
                    if triple == TRIPLE_DOUBLE or triple == TRIPLE_SINGLE:
                        if not in_docstring:
                            in_docstring = True
                            docstring_char = triple
                            j += 3
                        elif docstring_char == triple:
                            in_docstring = False
                            docstring_char = None
                            j += 3
                        else:
                            j += 1
                    else:
                        j += 1
                else:
                    j += 1
        
        return in_docstring
    
    def _is_string_literal_only(self, line: str) -> bool:
        """
        Cek apakah baris hanya berisi string literal Python.
    
        PENTING: Pattern ini TIDAK boleh match assignment yang mengandung
        kata kunci keamanan seperti password, secret, query, dll.
        """
        stripped = line.strip()
        if re.match(r'^return\s+[\{\[].*[\'"]', stripped):
            return True
        if re.match(r'^return\s+[\'"]', stripped):
            return True
        if re.match(r'^[^=]+=\s*f?[\'"]', stripped):
            var_name = stripped.split('=')[0].strip().lower()
            security_keywords = [
                'password', 'passwd', 'secret', 'api_key', 'token', 
                'db_password', 'aws_secret', 'private_key', 'query',
                'sql', 'select', 'insert', 'update', 'delete'
            ]
            if any(keyword in var_name for keyword in security_keywords):
                return False
            return True
    
        if re.match(r'^[\'"][^\'"]*[\'"]$', stripped):
            return True
    
        if re.match(r'^f[\'"][^\'"]*[\'"]$', stripped):
            return True
        if re.match(r'^[\'"][^\'"]*[\'"]\s*:', stripped):
            return True
    
        return False
    
    def _has_nosec_comment(self, line: str) -> bool:
        """Cek apakah baris memiliki komentar @nosec untuk bypass scan"""
        return '@nosec' in line or '# nosec' in line
    
    def _is_python_string_check(self, line: str) -> bool:
        '''
        Deteksi pola pengecekan string dalam Python (bukan eksekusi kode).
        Contoh:
          - if 'eval(' in line → True (pengecekan string, aman)
          - eval($input) → False (eksekusi kode, perlu di-scan)
        '''
        pattern = r"['\"][\w\.]+\(['\"]\s+(in|not in)\s+\w+"
        return bool(re.search(pattern, line))
    
    def scan_directory(self, root_dir: str, progress_callback: Optional[Callable] = None) -> Tuple[List[Dict], int]:
        """Scan seluruh direktori secara rekursif"""
        logger.info(f"Memulai scan directory: {root_dir}")
        
        all_issues = []
        total_files = 0
        
        try:
            for root, dirs, files in os.walk(root_dir):
                dirs[:] = [d for d in dirs if d not in self.ignored_dirs]
                
                for file in files:
                    if file in self.ignored_files:
                        continue
                    
                    ext = Path(file).suffix.lower()
                    if file.endswith('.blade.php'):
                        ext = '.blade.php'
                    
                    if ext in self.allowed_extensions:
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, root_dir)
                        total_files += 1
                        
                        if progress_callback:
                            progress_callback(total_files, relative_path)
                        
                        issues = self.scan_file(file_path)
                        
                        for issue in issues:
                            issue['file'] = relative_path
                            all_issues.append(issue)
            
            logger.info(f"Scan selesai. Total files: {total_files}, Total issues: {len(all_issues)}")
            return all_issues, total_files
            
        except PermissionError as e:
            logger.error(f"Permission denied saat scan directory: {e}")
            return all_issues, total_files
        except Exception as e:
            logger.exception(f"Error tidak terduga saat scan directory: {e}")
            return all_issues, total_files
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """Scan satu file untuk mendeteksi issues"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line_content in enumerate(lines, 1):
                line_idx = line_num - 1
                cleaned_line = line_content.strip()
                
                # Skip empty lines
                if not cleaned_line:
                    continue
                
                # Skip baris dengan komentar @nosec
                if self._has_nosec_comment(cleaned_line):
                    continue
                
                # Skip baris yang berada di dalam docstring Python
                if self._is_in_docstring(lines, line_idx):
                    continue
                
                # Skip baris yang hanya berisi string literal Python (termasuk f-string)
                if self._is_string_literal_only(cleaned_line):
                    continue
                
                # Skip baris yang merupakan pengecekan string Python
                if self._is_python_string_check(cleaned_line):
                    continue
                
                # Skip full-line comments (tapi tetap scan inline comment)
                if re.match(r'^\s*(//|#|/\*|\*)', cleaned_line):
                    continue
                
                # Check against all rules
                for rule in self.rules:
                    if rule['compiled_pattern'].search(line_content):
                        issues.append({
                            'id': rule['id'],
                            'severity': rule['severity'],
                            'kategori': rule['kategori'],
                            'line': line_num,
                            'content': cleaned_line[:120] + ('...' if len(cleaned_line) > 120 else ''),
                            'info': rule['info'],
                            'solusi': rule['solusi'],
                            'auto_fixable': rule.get('auto_fixable', False)
                        })
        
        except UnicodeDecodeError as e:
            logger.warning(f"Encoding error di {file_path}: {e}")
        except PermissionError as e:
            logger.error(f"Permission denied: {file_path}")
        except FileNotFoundError:
            logger.warning(f"File tidak ditemukan: {file_path}")
        except Exception as e:
            logger.exception(f"Error membaca {file_path}: {e}")
        
        return issues
    
    def get_stats(self) -> Dict:
        """Dapatkan statistik scanner"""
        return {
            'total_rules': len(self.rules),
            'ignored_dirs': len(self.ignored_dirs),
            'ignored_files': len(self.ignored_files),
            'allowed_extensions': len(self.allowed_extensions)
        }