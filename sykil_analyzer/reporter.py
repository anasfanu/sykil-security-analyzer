"""
SYKIL Reporter Module
Mengelola output laporan (console, JSON, HTML)
"""

import json
import os
from datetime import datetime
from typing import List, Dict
from pathlib import Path


def _get_data_path(filename: str) -> Path:
    """Dapatkan path absolut ke file data dalam package"""
    return Path(__file__).parent / 'data' / filename
# ANSI Colors
COLORS = {
    'GREEN': "\033[92m",
    'YELLOW': "\033[93m",
    'RED': "\033[91m",
    'BLUE': "\033[94m",
    'CYAN': "\033[96m",
    'MAGENTA': "\033[95m",
    'RESET': "\033[0m"
}


def _get_output_dir() -> Path:
    """Lazy load output directory dari config"""
    try:
        from config import get_output_dir
        return get_output_dir()
    except ImportError:
        return Path("C:/Sykil_Security_Analyzer/output")


class Reporter:
    @staticmethod
    def console_report(issues: List[Dict], total_files: int):
        """Output ke terminal dengan warna"""
        if not issues:
            print(f"\n{COLORS['GREEN']}[✓] 0 Masalah. Proyek Anda Bersih & Aman!{COLORS['RESET']}")
            return
        
        print(f"\n{COLORS['BLUE']}{'='*70}")
        print(f"{'SYKIL : HASIL PEMINDAIAN KEAMANAN':^70}")
        print(f"{'='*70}{COLORS['RESET']}\n")
        
        # Group by file
        issues_by_file = {}
        for issue in issues:
            file = issue['file']
            if file not in issues_by_file:
                issues_by_file[file] = []
            issues_by_file[file].append(issue)
        
        for file, file_issues in issues_by_file.items():
            print(f"{COLORS['RED']}[✗] FILE: {file}{COLORS['RESET']}")
            
            for issue in file_issues:
                sev_color = COLORS['RED'] if issue['severity'] == 'CRITICAL' else (
                    COLORS['YELLOW'] if issue['severity'] == 'HIGH' else COLORS['CYAN']
                )
                
                print(f"  {sev_color}[{issue['severity']}]{COLORS['RESET']} "
                      f"{COLORS['CYAN']}Baris {issue['line']:4d}:{COLORS['RESET']} {issue['content']}")
                print(f"    {COLORS['MAGENTA']}[{issue['id']}] Kategori:{COLORS['RESET']} {issue['kategori']}")
                print(f"    {COLORS['YELLOW']}Info    :{COLORS['RESET']} {issue['info']}")
                print(f"    {COLORS['GREEN']}Solusi  :{COLORS['RESET']} {issue['solusi']}")
                print("-" * 70)
        
        # Summary
        critical_count = sum(1 for i in issues if i['severity'] == 'CRITICAL')
        print(f"\n{COLORS['BLUE']}{'='*70}")
        print(f"{'SYKIL : RINGKASAN':^70}")
        print(f"{'='*70}{COLORS['RESET']}")
        print(f"Total File Diperiksa : {total_files}")
        print(f"Total Masalah        : {len(issues)}")
        
        if critical_count > 0:
            print(f"Celah CRITICAL       : {COLORS['RED']}{critical_count} Ditemukan!{COLORS['RESET']}")
    
    @staticmethod
    def display_manual_fixes(issues: List[Dict]):
        """Tampilkan panduan manual untuk issues yang tidak bisa di-fix otomatis"""
        
        # Cari manual_fixes.json di beberapa lokasi
        possible_paths = [
            Path("manual_fixes.json"),
            Path("C:/Sykil_Security_Analyzer/manual_fixes.json"),
            _get_data_path("manual_fixes.json"),  # ⭐ Dalam package
        ]
        
        manual_fixes_file = None
        for path in possible_paths:
            if path.exists():
                manual_fixes_file = path
                break
        
        if not manual_fixes_file:
            return
        
        try:
            with open(manual_fixes_file, 'r', encoding='utf-8') as f:
                manual_fixes_data = json.load(f)
            
            manual_fixes = {fix['rule_id']: fix for fix in manual_fixes_data.get('manual_fixes', [])}
        except Exception as e:
            print(f"{COLORS['RED']}[!] Error membaca manual_fixes.json: {e}{COLORS['RESET']}")
            return
        
        # Filter issues yang butuh manual fix
        unfixable_issues = [i for i in issues if i['id'] in manual_fixes]
        
        if not unfixable_issues:
            return
        
        print(f"\n{COLORS['BLUE']}{'='*70}")
        print(f"{'SYKIL : PANDUAN PERBAIKAN MANUAL':^70}")
        print(f"{'='*70}{COLORS['RESET']}\n")
        
        # Group by rule_id
        issues_by_rule = {}
        for issue in unfixable_issues:
            rule_id = issue['id']
            if rule_id not in issues_by_rule:
                issues_by_rule[rule_id] = []
            issues_by_rule[rule_id].append(issue)
        
        for rule_id, rule_issues in issues_by_rule.items():
            fix_info = manual_fixes.get(rule_id)
            if not fix_info:
                continue
            
            sev_color = COLORS['RED'] if fix_info['severity'] == 'CRITICAL' else (
                COLORS['YELLOW'] if fix_info['severity'] == 'HIGH' else COLORS['CYAN']
            )
            
            print(f"{sev_color}[{fix_info['severity']}]{COLORS['RESET']} {COLORS['CYAN']}{rule_id}{COLORS['RESET']} - {fix_info['kategori']}")
            print(f"  {COLORS['YELLOW']}Deskripsi:{COLORS['RESET']} {fix_info['description']}")
            print(f"  {COLORS['YELLOW']}Jumlah ditemukan:{COLORS['RESET']} {len(rule_issues)}")
            
            if fix_info.get('examples'):
                example = fix_info['examples'][0]
                print(f"\n  {COLORS['GREEN']}Contoh Perbaikan:{COLORS['RESET']}")
                print(f"  {COLORS['RED']}Sebelum:{COLORS['RESET']}")
                for line in example['before'].split('\n'):
                    print(f"    {line}")
                print(f"  {COLORS['GREEN']}Sesudah:{COLORS['RESET']}")
                for line in example['after'].split('\n'):
                    print(f"    {line}")
                
                print(f"\n  {COLORS['CYAN']}Langkah-langkah:{COLORS['RESET']}")
                for i, step in enumerate(example['steps'], 1):
                    print(f"    {i}. {step}")
            
            if fix_info.get('references'):
                print(f"\n  {COLORS['BLUE']}Referensi:{COLORS['RESET']}")
                for ref in fix_info['references']:
                    print(f"    • {ref}")
            
            print(f"\n{'-'*70}\n")
    
    @staticmethod
    def export_json(issues: List[Dict], total_files: int, target_dir: str, output_dir: str = None):
        """Export ke JSON dengan target_dir"""
        # Gunakan output_dir dari config jika tidak disediakan
        if output_dir is None:
            out_path = _get_output_dir()
        else:
            out_path = Path(output_dir)
        
        out_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sykil_report_{timestamp}.json"
        filepath = out_path / filename
        
        report = {
            'tool': 'SYKIL : Security Analyzer',
            'version': '1.0.0',
            'scan_date': datetime.now().isoformat(),
            'target_dir': os.path.abspath(target_dir),
            'total_files': total_files,
            'total_issues': len(issues),
            'critical_count': sum(1 for i in issues if i['severity'] == 'CRITICAL'),
            'issues': issues
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{COLORS['GREEN']}[✓] Laporan JSON disimpan: {filepath}{COLORS['RESET']}")
        return str(filepath)
    
    @staticmethod
    def export_html(issues: List[Dict], total_files: int, output_dir: str = None):
        """Export ke HTML"""
        if output_dir is None:
            out_path = _get_output_dir()
        else:
            out_path = Path(output_dir)
        
        out_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sykil_report_{timestamp}.html"
        filepath = out_path / filename
        
        # Load manual fixes untuk ditampilkan di HTML
        manual_fixes = {}
        possible_paths = [
            Path("manual_fixes.json"),
            Path("C:/Sykil_Security_Analyzer/manual_fixes.json"),
            _get_data_path("manual_fixes.json"),  # ⭐ Dalam package
        ]
        
        for path in possible_paths:
            if path.exists():
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        manual_fixes_data = json.load(f)
                        manual_fixes = {fix['rule_id']: fix for fix in manual_fixes_data.get('manual_fixes', [])}
                    break
                except Exception:
                    pass
        
        html_content = f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SYKIL : Security Analyzer - Laporan {datetime.now().strftime("%Y-%m-%d %H:%M")}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .brand {{ text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 3px solid #3498db; }}
        .brand h1 {{ color: #2c3e50; font-size: 2.2em; margin-bottom: 5px; }}
        .brand .tagline {{ color: #7f8c8d; font-style: italic; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .issue {{ background: #fff; border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; border-radius: 4px; }}
        .issue.CRITICAL {{ border-left-color: #c0392b; }}
        .issue.HIGH {{ border-left-color: #e67e22; }}
        .issue.MEDIUM {{ border-left-color: #f39c12; }}
        .issue.LOW {{ border-left-color: #3498db; }}
        .severity {{ display: inline-block; padding: 4px 12px; border-radius: 3px; color: white; font-weight: bold; font-size: 12px; }}
        .severity.CRITICAL {{ background: #c0392b; }}
        .severity.HIGH {{ background: #e67e22; }}
        .severity.MEDIUM {{ background: #f39c12; }}
        .severity.LOW {{ background: #3498db; }}
        .file-path {{ font-family: monospace; color: #7f8c8d; font-size: 14px; }}
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 13px; overflow-x: auto; white-space: pre-wrap; }}
        .info-label {{ font-weight: bold; color: #34495e; }}
        .manual-fixes {{ margin-top: 40px; }}
        .manual-fix {{ background: #fff; border-left: 4px solid #3498db; padding: 20px; margin: 20px 0; border-radius: 4px; }}
        .manual-fix h3 {{ color: #2c3e50; margin-bottom: 10px; }}
        .manual-fix h4 {{ color: #34495e; margin-top: 15px; margin-bottom: 10px; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #95a5a6; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="brand">
            <h1>🔒 SYKIL : Security Analyzer</h1>
            <div class="tagline">Smashing Vulnerabilities, Securing Code</div>
        </div>
        <p><strong>Tanggal Scan:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="summary">
            <h2>📊 Ringkasan</h2>
            <p><strong>Total File Diperiksa:</strong> {total_files}</p>
            <p><strong>Total Masalah Ditemukan:</strong> {len(issues)}</p>
            <p><strong>Celah CRITICAL:</strong> <span style="color: #c0392b; font-weight: bold;">{sum(1 for i in issues if i['severity'] == 'CRITICAL')}</span></p>
        </div>
        
        <h2>🚨 Detail Masalah</h2>
"""
        
        for issue in issues:
            html_content += f"""
        <div class="issue {issue['severity']}">
            <span class="severity {issue['severity']}">{issue['severity']}</span>
            <span class="file-path">{issue['file']} : Baris {issue['line']}</span>
            <h3>[{issue['id']}] {issue['kategori']}</h3>
            <div class="code">{issue['content']}</div>
            <p><span class="info-label">ℹ️ Informasi:</span> {issue['info']}</p>
            <p><span class="info-label">✅ Solusi:</span> {issue['solusi']}</p>
        </div>
"""
        
        # Tambahkan section manual fixes jika ada
        if manual_fixes and any(i['id'] in manual_fixes for i in issues):
            html_content += """
        <div class="manual-fixes">
            <h2>📖 Panduan Perbaikan Manual</h2>
            <p>Berikut adalah panduan detail untuk masalah yang memerlukan perbaikan manual:</p>
"""
            
            for rule_id, fix_info in manual_fixes.items():
                if any(i['id'] == rule_id for i in issues):
                    html_content += f"""
            <div class="manual-fix">
                <h3>[{rule_id}] {fix_info['kategori']}</h3>
                <p><strong>Deskripsi:</strong> {fix_info['description']}</p>
"""
                    
                    if fix_info.get('examples'):
                        example = fix_info['examples'][0]
                        html_content += f"""
                <h4>Contoh Perbaikan:</h4>
                <p><strong>Sebelum:</strong></p>
                <div class="code">{example['before']}</div>
                <p><strong>Sesudah:</strong></p>
                <div class="code">{example['after']}</div>
                <h4>Langkah-langkah:</h4>
                <ol>
"""
                        for step in example['steps']:
                            html_content += f"                    <li>{step}</li>\n"
                        html_content += "                </ol>\n"
                    
                    if fix_info.get('references'):
                        html_content += "                <h4>Referensi:</h4>\n                <ul>\n"
                        for ref in fix_info['references']:
                            html_content += f"                    <li><a href='{ref}' target='_blank'>{ref}</a></li>\n"
                        html_content += "                </ul>\n"
                    
                    html_content += "            </div>\n"
            
            html_content += "        </div>\n"
        
        html_content += """
        <div class="footer">
            <p>Laporan dibuat oleh <strong>SYKIL : Security Analyzer v1.0.0</strong></p>
            <p>Smashing Vulnerabilities, Securing Code</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{COLORS['GREEN']}[✓] Laporan HTML disimpan: {filepath}{COLORS['RESET']}")
        return str(filepath)