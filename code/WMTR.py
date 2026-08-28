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

# ============ Configuration ============
WORK_DIR = r"C:\Windows-Mining-Trojan-Remover"
LOG_DIR = r"C:\SysMonitorLogs"
INITIAL_LOG = os.path.join(LOG_DIR, "WMTR_initial_scan.log")
COMPARE_LOG = os.path.join(LOG_DIR, "WMTR_compare.log")
SYSMONITOR_EXE = os.path.join(WORK_DIR, "sys_monitor.exe")
WMTR_EXE = os.path.join(WORK_DIR, "WMTR.exe")

# Known malicious keywords (including English-word deception)
MALICIOUS_KEYWORDS = [
    # Mining trojans
    'UT7ejTkn', 'WE93mndC', 'WpSJj0lv', 'YRbL1xSX', 'RuntimeHost', 'RuntimeTask',
    '8B86CBC', '2FA7F989', 'ABE94A11', '15205438', 'D3F4E2A1', '50AB775E',
    'proxies-peer', '15AB6CF5', 'B95EB893', '5ghAHv', 'jHkYtN', 'zQM241sm',
    'nAumBAO1', 'lw5ypO', 'P41H56Vb', 'WE93mndC', 'KxDQmm', 'ccv', 'mzcv',
    'lolMiner', 'SRBMiner', 'gminer', 'miniZ', 'SecurityHealthHost',
    '0AzjkAEd', '6E7B6FD3', 'Diagnostics.Client', 'SimpleRunPE',
    # Remote control
    'ScreenConnect', 'Windows VC', 'rasedy', 'ConnectWise',
    # Mining pools / C2
    'kryptex', 'gleeze', '176.96.137.253', '217.216.109.4',
    # English-word deception (fake normal English task names)
    'Efficiently Achieve Analysis', 'productivity Deadlines Priority',
    'Windows System Health', 'Workflow Contingency', 'Elevate Plans Interface',
]


def is_admin():
    """Check if running with admin/NT/SYSTEM privileges"""
    try:
        # Check if SYSTEM
        if 'SYSTEM' in os.environ.get('USERNAME', '').upper():
            return True, 'SYSTEM'
        # Check if admin
        return ctypes.windll.shell32.IsUserAnAdmin() != 0, 'ADMIN'
    except Exception:
        return False, 'UNKNOWN'


def is_random_name(name):
    """Check if name looks like a virus random name (e.g. 5ghAHv, UT7ejTkn)"""
    base = os.path.splitext(name)[0]
    if len(base) < 6 or len(base) > 12:
        return False
    has_upper = any(c.isupper() for c in base)
    has_lower = any(c.islower() for c in base)
    has_digit = any(c.isdigit() for c in base)
    if has_upper and has_lower and has_digit:
        vowels = 'aeiouAEIOU'
        vowel_count = sum(1 for c in base if c in vowels)
        if vowel_count / len(base) < 0.25:
            return True
    return False


def now():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def run_cmd(cmd, timeout=30):
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

# 动态关键词：从启动项提取文件名并添加到关键词列表
def extract_startup_keywords():
    """Scan startup items, extract file names, dynamically add to keywords"""
    added = []
    keys = [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
    ]
    for k in keys:
        out = run_cmd(f'reg query "{k}"')
        # 提取所有 exe/dll 文件名
        for line in out.split('\n'):
            # 提取路径中的文件名
            import re as _re
            exes = _re.findall(r'[\\/]([A-Za-z0-9_]+\.(?:exe|dll|bat|cmd|ps1))', line, _re.IGNORECASE)
            for exe in exes:
                base = os.path.splitext(exe)[0]
                if base.lower() not in [k.lower() for k in MALICIOUS_KEYWORDS]:
                    # 只添加看起来可疑的（随机名或不在系统正常程序中的）
                    if is_random_name(exe) or base.lower() not in ['securityhealth', 'awe sun', 'onedrive', 'thunder', 'palminput', 'wujie', 'msedge']:
                        MALICIOUS_KEYWORDS.append(base)
                        added.append(f"Dynamic keyword added: {base}")
    return '\n'.join(added) if added else "No new dynamic keywords"




def scan_files():
    """Scan key folders for malicious files"""
    results = []
    base_dirs = [
        r'C:\ProgramData',
        r'C:\Users\Public',
        r'C:\Program Files (x86)',
        r'C:\Program Files',
        r'C:\Windows\Temp',
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
                for item in dirs + files:
                    full = os.path.join(root, item)
                    if any(k.lower() in (item + full).lower() for k in MALICIOUS_KEYWORDS):
                        results.append(f"MALICIOUS: {full}")
                    elif is_random_name(item) and item.lower().endswith(('.exe', '.dll', '.dat', '.tmp')):
                        results.append(f"RANDOM-NAME: {full}")
        except Exception:
            pass
    return '\n'.join(results) if results else "No malicious files found"


def scan_registry():
    """Scan registry startup items, dynamically add found paths to keywords"""
    results = []
    keys = [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
    ]
    for k in keys:
        out = run_cmd(f'reg query "{k}"')
        if any(m.lower() in out.lower() for m in MALICIOUS_KEYWORDS):
            results.append(f"REGISTRY SUSPICIOUS [{k}]: {out}")
        # Dynamically extract file names from startup paths
        import re as _re
        for line in out.split('\n'):
            exes = _re.findall(r'[\\/]([A-Za-z0-9_]+\.(?:exe|dll|bat|cmd|ps1))', line, _re.IGNORECASE)
            for exe in exes:
                base = os.path.splitext(exe)[0]
                if is_random_name(exe) and base.lower() not in [k.lower() for k in MALICIOUS_KEYWORDS]:
                    MALICIOUS_KEYWORDS.append(base)
                    results.append(f"DYNAMIC keyword from startup: {base}")
    return '\n'.join(results) if results else "Registry startup items clean"


def scan_tasks():
    """Scan scheduled tasks (including English-word deception)"""
    results = []
    tasks_dir = r'C:\Windows\System32\Tasks'
    if os.path.exists(tasks_dir):
        for root, dirs, files in os.walk(tasks_dir):
            for f in files:
                full = os.path.join(root, f)
                try:
                    with open(full, 'r', encoding='utf-8', errors='ignore') as fh:
                        content = fh.read()
                    if any(k.lower() in content.lower() for k in MALICIOUS_KEYWORDS):
                        results.append(f"TASK SUSPICIOUS: {full}")
                except Exception:
                    pass
    return '\n'.join(results) if results else "Scheduled tasks clean"


def scan_processes():
    """Scan running malicious processes"""
    results = []
    out = run_cmd('wmic process get name,processid,executablepath /format:csv')
    for line in out.split('\n'):
        if any(k.lower() in line.lower() for k in MALICIOUS_KEYWORDS):
            results.append(f"PROCESS SUSPICIOUS: {line.strip()}")
    return '\n'.join(results) if results else "No malicious processes"


def scan_network():
    """Scan malicious network connections"""
    results = []
    out = run_cmd('netstat -ano')
    for line in out.split('\n'):
        if any(p in line for p in ['kryptex', 'gleeze', 'rasedy', '176.96.137.253', '217.216.109.4', ':4041', ':8041', ':8443']):
            results.append(f"NETWORK SUSPICIOUS: {line.strip()}")
    return '\n'.join(results) if results else "No malicious network connections"


# ============ 2. Cleanup Phase ============

def kill_processes():
    """Kill malicious processes"""
    procs = ['UT7ejTkn', 'WE93mndC', 'WpSJj0lv', 'YRbL1xSX', 'RuntimeHost',
             'RuntimeTask', 'ScreenConnect', 'lolMiner', 'SRBMiner', 'gminer',
             'miniZ', 'lw5ypO', 'P41H56Vb', 'KxDQmm', 'ccv', 'mzcv']
    killed = []
    for p in procs:
        result = run_cmd(f'taskkill /F /IM {p}.exe 2>nul')
        if 'SUCCESS' in result.upper() or '成功' in result:
            killed.append(f"{p}.exe")
    return '\n'.join(killed) if killed else "No malicious processes to kill"


def delete_files():
    """Delete malicious files"""
    deleted = []
    mal_dirs = [
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
    for d in mal_dirs:
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
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" /f',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes" /f',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions" /f',
        'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions" /f',
        'schtasks /delete /tn "Efficiently Achieve Analysis Your" /f',
        'schtasks /delete /tn "productivity Deadlines Priority" /f',
        'schtasks /delete /tn "Windows System Health" /f',
        'schtasks /delete /tn "Workflow Contingency Delegation With Maximum" /f',
        'schtasks /delete /tn "Elevate Plans Interface productivity Organize" /f',
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
    """Setup sys_monitor and WMTR autostart (add 2 registry Run entries each)"""
    added = []
    if os.path.exists(SYSMONITOR_EXE):
        run_cmd(f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SysMonitor" /t REG_SZ /d "{SYSMONITOR_EXE}" /f')
        run_cmd(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SysMonitor" /t REG_SZ /d "{SYSMONITOR_EXE}" /f')
        added.append("Added SysMonitor to HKLM/HKCU Run")
    if os.path.exists(WMTR_EXE):
        run_cmd(f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WMTR" /t REG_SZ /d "{WMTR_EXE}" /f')
        run_cmd(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WMTR" /t REG_SZ /d "{WMTR_EXE}" /f')
        added.append("Added WMTR to HKLM/HKCU Run")
    return '\n'.join(added) if added else "Autostart setup complete"


def remove_autostart():
    """Remove autostart for both exe when confirmed clean"""
    removed = []
    run_cmd('reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SysMonitor" /f')
    run_cmd('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SysMonitor" /f')
    run_cmd('reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WMTR" /f')
    run_cmd('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WMTR" /f')
    removed.append("Removed SysMonitor and WMTR autostart from registry")
    return '\n'.join(removed)


# ============ 4. Log Saving ============

def save_initial_log():
    """Save initial scan record"""
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
    latest = max(logs, key=lambda f: (os.path.getmtime(os.path.join(LOG_DIR, f)), os.path.getsize(os.path.join(LOG_DIR, f))))
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
        for root, dirs, files in os.walk(base):
            for item in dirs + files:
                if is_random_name(item):
                    results.append(f"Random name: {os.path.join(root, item)}")
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
    # Step 0: Scan startup items FIRST to dynamically add keywords
    print("\n[0/8] Scanning startup items (dynamic keyword extraction)...")
    dyn = extract_startup_keywords()
    print(dyn)
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

    # Setup autostart
    print("\n[7/8] Setting up autostart...")
    print(setup_autostart())

    # Save initial log
    print("\n[8/8] Saving initial scan record...")

    # Save initial log
    print("\nSaving initial scan record...")
    log_file = save_initial_log()
    print(f"Log saved: {log_file}")

    # Random name check
    print("\nRandom name checker...")
    print(random_name_checker())

    # Ask to restart
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
