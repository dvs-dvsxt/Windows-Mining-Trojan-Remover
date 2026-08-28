# -*- coding: utf-8 -*-
"""
WMTR.py - Windows Mining Trojan Remover
One-click antivirus script
Features:
1. Scan key folders, startup items, registry (including English-word deception)
2. Delete files + kill processes + restore registry + restore security software
3. Setup autostart (add 2 registry Run entries)
4. Ask to restart, save scan log
5. After restart, auto-compare logs to detect old/new viruses
6. Built-in random-name checker
7. Auto-remove autostart when confirmed clean
8. Check admin/NT/SYSTEM privileges
"""
import os
import sys
import time
import subprocess
import datetime
import shutil
import ctypes
import re

# ============ Configuration ============
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORK_DIR = SCRIPT_DIR
LOG_DIR = r"C:\SysMonitorLogs"
INITIAL_LOG = os.path.join(LOG_DIR, "WMTR_initial_scan.log")
COMPARE_LOG = os.path.join(LOG_DIR, "WMTR_compare.log")
SYSMONITOR_EXE = os.path.join(WORK_DIR, "sys_monitor.exe")
WMTR_EXE = os.path.join(WORK_DIR, "WMTR.exe")

# Known malicious keywords (AweSun removed - legitimate software)
MALICIOUS_KEYWORDS = [
    # Mining trojans
    'UT7ejTkn', 'WE93mndC', 'WpSJj0lv', 'YRbL1xSX', 'RuntimeHost', 'RuntimeTask',
    '8B86CBC', '2FA7F989', 'ABE94A11', '15205438', 'D3F4E2A1', '50AB775E',
    'proxies-peer', '15AB6CF5', 'B95EB893', '5ghAHv', 'jHkYtN', 'zQM241sm',
    'nAumBAO1', 'lw5ypO', 'P41H56Vb', 'KxDQmm', 'ccv', 'mzcv',
    'lolMiner', 'SRBMiner', 'gminer', 'miniZ', 'SecurityHealthHost',
    '0AzjkAEd', '6E7B6FD3', 'Diagnostics.Client', 'SimpleRunPE',
    # Remote control (malicious variants)
    'ScreenConnect', 'Windows VC', 'rasedy', 'ConnectWise',
    # Mining pools / C2
    'kryptex', 'gleeze', '176.96.137.253', '217.216.109.4',
    # English-word deception (fake normal task names)
    'Efficiently Achieve Analysis', 'productivity Deadlines Priority',
    'Windows System Health', 'Workflow Contingency', 'Elevate Plans Interface',
]

# Whitelist - legitimate program names (case insensitive)
WHITELIST_NAMES = {
    # System
    'securityhealth', 'securityhealthsystray', 'runtimebroker', 'svchost',
    'services', 'lsass', 'winlogon', 'explorer', 'taskhostw', 'dwm',
    'csrss', 'smss', 'wininit', 'conhost', 'system', 'registry',
    'ctfmon', 'sihost', 'fontdrvhost', 'dllhost', 'spoolsv',
    # Legitimate software
    'awesun', 'awesun_guard', 'onedrive', 'onedrivesetup', 'thunder',
    'palminput', 'palminputstartup', 'wujie', 'msedge', 'microsoftedge',
    # CrystalDisk
    'diskmark64', 'diskspd64', 'diskspd64l',
}

# Whitelist path prefixes - skip these directories entirely
WHITELIST_PATHS = [
    r'C:\Windows\System32',
    r'C:\Windows\SysWOW64',
    r'C:\Windows\Microsoft.NET',
    r'C:\Program Files\WindowsApps',
    r'C:\Program Files\Common Files\microsoft shared',
    r'C:\Program Files\Microsoft Office',
    r'C:\Program Files (x86)\Microsoft',
    r'C:\Program Files (x86)\Thunder Network',
    r'D:\Program Files (x86)\PalmInput',
    r'D:\leidian\wujie',
    r'C:\Program Files\CrystalDiskInfo',
    r'C:\Program Files\CrystalDiskMark',
    r'C:\Program Files\Oray\AweSun',
    r'C:\ProgramData\Oray\AweSun',
]

# Storage for detected items
_found_malicious_files = []
_found_malicious_processes = []


def is_admin():
    """Check if running with admin/NT/SYSTEM privileges"""
    try:
        if 'SYSTEM' in os.environ.get('USERNAME', '').upper():
            return True, 'SYSTEM'
        return ctypes.windll.shell32.IsUserAnAdmin() != 0, 'ADMIN'
    except Exception:
        return False, 'UNKNOWN'


def is_whitelisted_path(path):
    """Check if path is in whitelist"""
    if not path:
        return False
    path_lower = path.lower()
    for wp in WHITELIST_PATHS:
        if wp.lower() in path_lower:
            return True
    return False


def is_whitelisted_name(name):
    """Check if filename is in whitelist"""
    if not name:
        return False
    base = os.path.splitext(name)[0].lower()
    return base in WHITELIST_NAMES


def is_random_name(name):
    """Check if name looks like a random virus name (whitelist excluded)"""
    if not name:
        return False
    
    base = os.path.splitext(name)[0]
    
    # Skip if whitelisted
    if is_whitelisted_name(name):
        return False
    
    # Only check executable/dll types
    ext = os.path.splitext(name)[1].lower()
    if ext not in ['.exe', '.dll', '.dat', '.tmp', '.sys', '.bin']:
        return False
    
    # Length check
    if len(base) < 6 or len(base) > 14:
        return False
    
    # Must have mixed case and digits
    has_upper = any(c.isupper() for c in base)
    has_lower = any(c.islower() for c in base)
    has_digit = any(c.isdigit() for c in base)
    
    if has_upper and has_lower and has_digit:
        # Low vowel ratio (random names typically have few vowels)
        vowels = 'aeiouAEIOU'
        vowel_count = sum(1 for c in base if c in vowels)
        if vowel_count / len(base) < 0.2:
            return True
    
    return False


def now():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def run_cmd(cmd, timeout=30):
    """Execute command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=timeout, errors='ignore')
        return result.stdout + result.stderr
    except Exception as e:
        return f"ERROR: {e}"


def log_write(f, section, content):
    f.write(f"\n{'='*60}\n[{section}] - {now()}\n{'='*60}\n")
    f.write(content + "\n")
    f.flush()


# ============ 1. Scan Phase ============

def extract_startup_keywords():
    """Scan startup items, extract file names, dynamically add to keywords"""
    added = []
    keys = [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    ]
    
    for k in keys:
        out = run_cmd(f'reg query "{k}" 2>nul')
        if not out or 'ERROR' in out:
            continue
            
        for line in out.split('\n'):
            exes = re.findall(r'[\\/]([A-Za-z0-9_]+\.(?:exe|dll|bat|cmd|ps1))', line, re.IGNORECASE)
            for exe in exes:
                if not is_whitelisted_name(exe) and is_random_name(exe):
                    base = os.path.splitext(exe)[0]
                    if base.lower() not in [k.lower() for k in MALICIOUS_KEYWORDS]:
                        MALICIOUS_KEYWORDS.append(base)
                        added.append(f"Dynamic keyword added: {base}")
    return '\n'.join(added) if added else "No new dynamic keywords"


def scan_files():
    """Scan key folders for malicious files"""
    global _found_malicious_files
    _found_malicious_files = []
    results = []
    
    base_dirs = [
        r'C:\ProgramData',
        r'C:\Users\Public',
        r'C:\Windows\Temp',
        r'C:\Program Files',
        r'C:\Program Files (x86)',
    ]
    
    for base in base_dirs:
        if not os.path.exists(base):
            continue
        try:
            for root, dirs, files in os.walk(base):
                depth = root[len(base):].count(os.sep)
                if depth > 4:
                    dirs[:] = []
                    continue
                
                if is_whitelisted_path(root):
                    continue
                
                for item in dirs + files:
                    full = os.path.join(root, item)
                    
                    if is_whitelisted_path(full):
                        continue
                    if is_whitelisted_name(item):
                        continue
                    
                    # Check for malicious keywords
                    is_malicious = False
                    for kw in MALICIOUS_KEYWORDS:
                        if kw.lower() in item.lower() or kw.lower() in full.lower():
                            is_malicious = True
                            break
                    
                    if is_malicious:
                        results.append(f"MALICIOUS: {full}")
                        _found_malicious_files.append(full)
                    elif is_random_name(item):
                        results.append(f"RANDOM-NAME: {full}")
                        
        except Exception:
            pass
    
    return '\n'.join(results) if results else "No malicious files found"


def scan_registry():
    """Scan registry startup items"""
    results = []
    keys = [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    ]
    
    for k in keys:
        out = run_cmd(f'reg query "{k}" 2>nul')
        if not out or 'ERROR' in out:
            continue
        
        # Check if any malicious keyword is in the registry output
        found = False
        for kw in MALICIOUS_KEYWORDS:
            if kw.lower() in out.lower():
                found = True
                break
        
        if found:
            results.append(f"REGISTRY SUSPICIOUS [{k}]:\n{out}")
    
    return '\n'.join(results) if results else "Registry startup items clean"


def scan_tasks():
    """Scan scheduled tasks (including English-word deception)"""
    results = []
    tasks_dir = r'C:\Windows\System32\Tasks'
    if os.path.exists(tasks_dir):
        try:
            for root, dirs, files in os.walk(tasks_dir):
                # Limit depth
                depth = root[len(tasks_dir):].count(os.sep)
                if depth > 3:
                    continue
                for f in files:
                    full = os.path.join(root, f)
                    try:
                        with open(full, 'r', encoding='utf-8', errors='ignore') as fh:
                            content = fh.read()
                        for kw in MALICIOUS_KEYWORDS:
                            if kw.lower() in content.lower():
                                results.append(f"TASK SUSPICIOUS: {full}")
                                break
                    except Exception:
                        pass
        except Exception:
            pass
    
    return '\n'.join(results) if results else "Scheduled tasks clean"


def scan_processes():
    """Scan running malicious processes"""
    global _found_malicious_processes
    _found_malicious_processes = []
    results = []
    
    # Use PowerShell Get-Process (more reliable than wmic which is deprecated)
    out = run_cmd('powershell -NoProfile -Command "Get-Process | ForEach-Object { $_.ProcessName + \'|\' + $_.Id + \'|\' + $_.Path }"')
    
    for line in out.split('\n'):
        if '|' not in line:
            continue
        parts = line.split('|')
        if len(parts) < 2:
            continue
        
        name = parts[0].strip()
        pid = parts[1].strip() if len(parts) > 1 else ''
        path = parts[2].strip() if len(parts) > 2 else ''
        
        # Skip whitelisted names
        if is_whitelisted_name(name):
            continue
        
        # Check if malicious
        is_malicious = False
        for kw in MALICIOUS_KEYWORDS:
            if kw.lower() in name.lower() or (path and kw.lower() in path.lower()):
                is_malicious = True
                break
        
        if is_malicious:
            results.append(f"PROCESS SUSPICIOUS: {name}, {path}, {pid}")
            _found_malicious_processes.append({'name': name, 'path': path, 'pid': pid})
    
    return '\n'.join(results) if results else "No malicious processes"


def scan_network():
    """Scan malicious network connections"""
    results = []
    out = run_cmd('netstat -ano')
    for line in out.split('\n'):
        for kw in ['kryptex', 'gleeze', 'rasedy', '176.96.137.253', '217.216.109.4', ':4041', ':8041', ':8443']:
            if kw.lower() in line.lower():
                results.append(f"NETWORK SUSPICIOUS: {line.strip()}")
                break
    return '\n'.join(results) if results else "No malicious network connections"


# ============ 2. Cleanup Phase ============

def kill_processes():
    """Kill malicious processes"""
    global _found_malicious_processes
    killed = []
    
    # Use the detected processes from scan
    for proc in _found_malicious_processes:
        pid = proc.get('pid', '')
        if pid and pid.isdigit():
            result = run_cmd(f'taskkill /F /PID {pid} 2>nul')
            if 'SUCCESS' in result.upper() or '成功' in result:
                killed.append(f"{proc['name']} (PID: {pid})")
    
    # Also try killing by name (fallback)
    for kw in ['UT7ejTkn', 'WE93mndC', 'WpSJj0lv', 'YRbL1xSX', 'RuntimeHost',
               'RuntimeTask', 'ScreenConnect', 'lolMiner', 'SRBMiner', 'gminer',
               'miniZ', 'lw5ypO', 'P41H56Vb', 'KxDQmm', 'ccv', 'mzcv']:
        result = run_cmd(f'taskkill /F /IM {kw}.exe 2>nul')
        if 'SUCCESS' in result.upper() or '成功' in result:
            killed.append(f"{kw}.exe")
    
    return '\n'.join(killed) if killed else "No malicious processes to kill"


def delete_files():
    """Delete malicious files found during scan"""
    global _found_malicious_files
    deleted = []
    
    for filepath in _found_malicious_files:
        try:
            if os.path.exists(filepath):
                if os.path.isfile(filepath):
                    os.remove(filepath)
                    deleted.append(f"Deleted: {filepath}")
                elif os.path.isdir(filepath):
                    shutil.rmtree(filepath, ignore_errors=True)
                    deleted.append(f"Deleted dir: {filepath}")
        except Exception as e:
            deleted.append(f"Delete failed: {filepath} | {e}")
    
    # Also delete known malicious directories
    known_dirs = [
        r'C:\ProgramData\UT7ejTkn.exe',
        r'C:\ProgramData\TfuSTvhb',
        r'C:\ProgramData\0AzjkAEd',
        r'C:\ProgramData\6E7B6FD3',
        r'C:\ProgramData\proxies-peer',
        r'C:\ProgramData\15AB6CF5',
        r'C:\ProgramData\B95EB893',
        r'C:\Program Files (x86)\Windows VC',
        r'C:\Program Files (x86)\Common Files\Microsoft Shared\2FA7F989',
    ]
    
    for d in known_dirs:
        if os.path.exists(d):
            try:
                if os.path.isfile(d):
                    os.remove(d)
                else:
                    shutil.rmtree(d, ignore_errors=True)
                deleted.append(f"Deleted: {d}")
            except Exception as e:
                deleted.append(f"Delete failed: {d} | {e}")
    
    return '\n'.join(deleted) if deleted else "No malicious files to delete"


def restore_registry():
    """Restore registry (remove malicious exclusions and startup items)"""
    restored = []
    cmds = [
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" /f 2>nul',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes" /f 2>nul',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions" /f 2>nul',
        'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions" /f 2>nul',
        'schtasks /delete /tn "Efficiently Achieve Analysis Your" /f 2>nul',
        'schtasks /delete /tn "productivity Deadlines Priority" /f 2>nul',
        'schtasks /delete /tn "Windows System Health" /f 2>nul',
        'schtasks /delete /tn "Workflow Contingency Delegation With Maximum" /f 2>nul',
        'schtasks /delete /tn "Elevate Plans Interface productivity Organize" /f 2>nul',
    ]
    for cmd in cmds:
        run_cmd(cmd)
        restored.append(cmd)
    return '\n'.join(restored)


def restore_security():
    """Restore security software (prompt user to disable protection, wait 15s)"""
    print("[Security Restore] Please manually disable 'Tamper Protection' in Windows Security")
    print("[Security Restore] Waiting 15 seconds...")
    time.sleep(15)
    out = run_cmd('powershell -NoProfile -Command "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; Write-Output $s.IsTamperProtected"')
    if 'False' in out:
        return "Tamper Protection disabled, cleanup can proceed"
    else:
        return "Tamper Protection still enabled, some operations may be limited"


# ============ 3. Autostart Setup ============

def setup_autostart():
    """Setup sys_monitor and WMTR autostart"""
    added = []
    if os.path.exists(SYSMONITOR_EXE):
        run_cmd(f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SysMonitor" /t REG_SZ /d "{SYSMONITOR_EXE}" /f 2>nul')
        run_cmd(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SysMonitor" /t REG_SZ /d "{SYSMONITOR_EXE}" /f 2>nul')
        added.append("Added SysMonitor to HKLM/HKCU Run")
    if os.path.exists(WMTR_EXE):
        run_cmd(f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WMTR" /t REG_SZ /d "{WMTR_EXE}" /f 2>nul')
        run_cmd(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WMTR" /t REG_SZ /d "{WMTR_EXE}" /f 2>nul')
        added.append("Added WMTR to HKLM/HKCU Run")
    return '\n'.join(added) if added else "Autostart setup complete"


def remove_autostart():
    """Remove autostart for both exe when confirmed clean"""
    removed = []
    run_cmd('reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SysMonitor" /f 2>nul')
    run_cmd('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SysMonitor" /f 2>nul')
    run_cmd('reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WMTR" /f 2>nul')
    run_cmd('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WMTR" /f 2>nul')
    removed.append("Removed SysMonitor and WMTR autostart from registry")
    return '\n'.join(removed)


# ============ 4. Log Saving ============

def save_initial_log():
    """Save initial scan record"""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except Exception:
        pass
    
    with open(INITIAL_LOG, 'w', encoding='utf-8') as f:
        f.write(f"WMTR Initial Scan Record\nTime: {now()}\n")
        log_write(f, "1. Malicious File Scan", scan_files())
        log_write(f, "2. Registry Startup Items", scan_registry())
        log_write(f, "3. Scheduled Tasks", scan_tasks())
        log_write(f, "4. Malicious Processes", scan_processes())
        log_write(f, "5. Malicious Network", scan_network())
        log_write(f, "6. Killed Processes", kill_processes())
        log_write(f, "7. Deleted Files", delete_files())
        log_write(f, "8. Registry Restore", restore_registry())
        log_write(f, "9. Security Restore", restore_security())
    return INITIAL_LOG


# ============ 5. Post-restart Compare ============

def compare_logs():
    """Compare logs after restart to detect old/new viruses"""
    results = []
    if not os.path.exists(LOG_DIR):
        return "Log directory does not exist"
    
    logs = [f for f in os.listdir(LOG_DIR) if f.startswith('continuous_monitor_')]
    if not logs:
        return "No monitor logs found"
    
    latest = max(logs, key=lambda f: os.path.getmtime(os.path.join(LOG_DIR, f)))
    latest_path = os.path.join(LOG_DIR, latest)
    
    with open(latest_path, 'r', encoding='utf-8') as f:
        latest_content = f.read()

    old_viruses = []
    if os.path.exists(INITIAL_LOG):
        with open(INITIAL_LOG, 'r', encoding='utf-8') as f:
            old_content = f.read()
        for kw in MALICIOUS_KEYWORDS:
            if kw in old_content:
                old_viruses.append(kw)

    old_still_present = []
    old_cleared = []
    for v in old_viruses:
        if v in latest_content:
            old_still_present.append(v)
        else:
            old_cleared.append(v)

    results.append("=== OLD VIRUS COMPARISON ===")
    results.append(f"Cleared: {', '.join(old_cleared) if old_cleared else 'None'}")
    results.append(f"Still present: {', '.join(old_still_present) if old_still_present else 'None'}")

    new_viruses = []
    for kw in MALICIOUS_KEYWORDS:
        if kw in latest_content and kw not in old_viruses:
            new_viruses.append(kw)

    results.append("\n=== NEW VIRUS DETECTION ===")
    results.append(f"New found: {', '.join(new_viruses) if new_viruses else 'None'}")

    return '\n'.join(results)


# ============ 6. Random Name Checker ============

def random_name_checker():
    """Built-in random-name checker"""
    results = []
    scan_dirs = [r'C:\ProgramData', r'C:\Users\Public', r'C:\Windows\Temp']
    for base in scan_dirs:
        if not os.path.exists(base):
            continue
        try:
            for root, dirs, files in os.walk(base):
                if is_whitelisted_path(root):
                    continue
                for item in dirs + files:
                    if not is_whitelisted_name(item) and is_random_name(item):
                        results.append(f"Random name: {os.path.join(root, item)}")
        except Exception:
            pass
    return '\n'.join(results) if results else "No random-named files found"


# ============ Main Flow ============

def main():
    print("=" * 60)
    print("WMTR - Windows Mining Trojan Remover")
    print("One-click antivirus script")
    print("=" * 60)

    # Check admin privileges
    admin, priv_type = is_admin()
    if not admin:
        print("\n[ERROR] Insufficient privileges!")
        print("Please run this program as Administrator or SYSTEM.")
        print("Right-click the exe and select 'Run as administrator'.")
        input("Press Enter to exit...")
        return
    print(f"\n[OK] Running with {priv_type} privileges")

    # Check if post-restart mode
    restart_marker = os.path.join(WORK_DIR, "restart_marker.txt")
    if os.path.exists(restart_marker):
        print("\n[Post-restart Mode] Restart marker detected, comparing logs...")
        os.remove(restart_marker)
        result = compare_logs()
        print(result)

        # If clean, remove autostart
        if "Still present: None" in result and "New found: None" in result:
            print("\n[OK] System confirmed clean!")
            print("[OK] Removing autostart for both exe...")
            print(remove_autostart())
            print("[OK] Autostart removed. Antivirus tools will not auto-start.")
        else:
            print("\n[WARNING] Viruses still detected or new viruses found!")
            print("Please run the cleanup again.")

        with open(COMPARE_LOG, 'w', encoding='utf-8') as f:
            f.write(f"WMTR Post-restart Compare\nTime: {now()}\n{result}\n")
        print(f"\nCompare result saved: {COMPARE_LOG}")
        input("Press Enter to exit...")
        return

    # First run mode
    print("\n[0/8] Scanning startup items (dynamic keyword extraction)...")
    print(extract_startup_keywords())
    print(scan_registry())

    print("\n[1/8] Scanning malicious files...")
    print(scan_files())
    
    print("\n[2/8] Scanning scheduled tasks...")
    print(scan_tasks())
    
    print("\n[3/8] Scanning malicious processes...")
    print(scan_processes())
    
    print("\n[4/8] Killing malicious processes...")
    print(kill_processes())
    
    print("\n[5/8] Deleting malicious files...")
    print(delete_files())
    
    print("\n[6/8] Restoring registry + security software...")
    print(restore_registry())
    print(restore_security())

    print("\n[7/8] Setting up autostart...")
    print(setup_autostart())

    print("\n[8/8] Saving initial scan record...")
    log_file = save_initial_log()
    print(f"Log saved: {log_file}")

    print("\nRandom name checker...")
    print(random_name_checker())

    print("\n" + "=" * 60)
    choice = input("Restart now? (y/n): ").strip().lower()
    if choice == 'y':
        with open(restart_marker, 'w') as f:
            f.write(now())
        print("Restarting...")
        run_cmd('shutdown /r /t 5')
    else:
        print("Not restarting. Please restart manually to complete comparison.")


if __name__ == '__main__':
    main()
