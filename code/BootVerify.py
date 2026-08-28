# -*- coding: utf-8 -*-
"""
BootVerify.py - Boot Sector Insurance Verification Script
Verifies MBR, EFI, and WMI persistence for trojan infection
Uses Python libs, system tools, and BOOTICE.exe
"""
import os
import sys
import time
import subprocess
import datetime
import ctypes
import json

# ============ Configuration ============
WORK_DIR = r"C:\Windows-Mining-Trojan-Remover"
BOOTICE = os.path.join(WORK_DIR, "BOOTICE.exe")
REPORT_FILE = os.path.join(WORK_DIR, "BootVerify_Report.txt")
MBR_BACKUP = os.path.join(WORK_DIR, "MBR_backup.bin")

# Suspicious keywords for detection
SUSPICIOUS_KEYWORDS = [
    'UT7ejTkn', 'WE93mndC', 'WpSJj0lv', 'YRbL1xSX', 'RuntimeHost', 'RuntimeTask',
    'ScreenConnect', 'kryptex', 'gleeze', 'rasedy', 'lolMiner', 'SRBMiner',
    'gminer', 'miniZ', 'Diagnostics.Client', 'SimpleRunPE', 'ccv', 'mzcv',
    'Windows VC', 'proxies-peer', '15AB6CF5', 'B95EB893', '0AzjkAEd', '6E7B6FD3',
    'TfuSTvhb', '5ghAHv', 'jHkYtN', 'zQM241sm', 'nAumBAO1', 'lw5ypO',
    'P41H56Vb', 'KxDQmm', '8B86CBC', '2FA7F989', 'ABE94A11', 'SecurityHealthHost',
    'Efficiently Achieve Analysis', 'productivity Deadlines Priority',
    'Windows System Health', 'Workflow Contingency', 'Elevate Plans Interface',
]


def is_admin():
    """Check admin privileges"""
    try:
        if 'SYSTEM' in os.environ.get('USERNAME', '').upper():
            return True, 'SYSTEM'
        return ctypes.windll.shell32.IsUserAnAdmin() != 0, 'ADMIN'
    except Exception:
        return False, 'UNKNOWN'


def now():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def run_cmd(cmd, timeout=60):
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


# ============ 1. MBR Verification ============

def verify_mbr():
    """Verify MBR using BOOTICE"""
    results = []
    if not os.path.exists(BOOTICE):
        return "BOOTICE not found, cannot verify MBR"

    # Backup MBR
    result = run_cmd(f'"{BOOTICE}" /DEVICE=0:0 /mbr /backup /file="{MBR_BACKUP}" /sectors=1 /quiet')
    if os.path.exists(MBR_BACKUP):
        results.append(f"MBR backup created: {MBR_BACKUP}")
        # Read MBR content
        try:
            with open(MBR_BACKUP, 'rb') as f:
                mbr = f.read()
            results.append(f"MBR size: {len(mbr)} bytes")
            # Check signature (last 2 bytes should be 55 AA)
            if len(mbr) >= 2:
                sig = mbr[-2:]
                if sig == b'\x55\xAA':
                    results.append("MBR signature: 55 AA (VALID)")
                else:
                    results.append(f"MBR signature: {sig.hex().upper()} (INVALID!)")
            # Check partition table type (EE = GPT)
            if len(mbr) >= 447:
                pt_type = mbr[450]  # First partition type at offset 450
                if pt_type == 0xEE:
                    results.append("Partition table: GPT (EE type)")
                elif pt_type == 0x00:
                    results.append("Partition table: Empty")
                else:
                    results.append(f"Partition table type: 0x{pt_type:02X}")
            # Check for suspicious boot code (first 446 bytes)
            boot_code = mbr[:446]
            if boot_code.count(b'\x00') > 400:
                results.append("Boot code: Mostly empty (normal for GPT)")
            else:
                results.append("Boot code: Present (check for anomalies)")
        except Exception as e:
            results.append(f"MBR read error: {e}")
    else:
        results.append("MBR backup FAILED")

    # Get disk info
    result2 = run_cmd(f'"{BOOTICE}" /diskinfo /list /file="{WORK_DIR}\\diskinfo.txt" /quiet')
    if os.path.exists(os.path.join(WORK_DIR, 'diskinfo.txt')):
        with open(os.path.join(WORK_DIR, 'diskinfo.txt'), 'r', encoding='utf-8', errors='ignore') as f:
            results.append("Disk info:\n" + f.read())

    return '\n'.join(results)


# ============ 2. EFI Verification ============

def verify_efi():
    """Verify EFI boot entries and ESP content"""
    results = []

    # Check BCD boot entries
    bcd = run_cmd('bcdedit /enum firmware')
    results.append("=== BCD Firmware Boot Entries ===")
    results.append(bcd)

    # Check for suspicious boot entries
    suspicious_entries = []
    for line in bcd.split('\n'):
        if 'description' in line.lower():
            desc = line.split('description')[1].strip() if 'description' in line else ''
            # Check for suspicious descriptions
            for kw in SUSPICIOUS_KEYWORDS:
                if kw.lower() in desc.lower():
                    suspicious_entries.append(f"Suspicious boot entry: {desc}")
    if suspicious_entries:
        results.append("\n=== SUSPICIOUS BOOT ENTRIES ===")
        results.extend(suspicious_entries)
    else:
        results.append("\nNo suspicious boot entries found")

    # Check ESP content
    results.append("\n=== EFI System Partition Check ===")
    # Try to find ESP and list EFI directory
    ps_cmd = r'''
    $esp = Get-Partition | Where-Object { $_.Type -eq 'EFI System Partition' }
    if ($esp) {
        $esp | Format-List DiskNumber,PartitionNumber,DriveLetter,Size
    } else {
        Write-Output "No ESP found"
    }
    '''
    import base64
    encoded = base64.b64encode(ps_cmd.encode('utf-16-le')).decode('ascii')
    esp_info = run_cmd(f'powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}')
    results.append(esp_info)

    return '\n'.join(results)


# ============ 3. WMI Verification ============

def verify_wmi():
    """Verify WMI persistence"""
    results = []

    # Check WMI event filters
    filters = run_cmd('wmic /namespace:\\\\root\\subscription path __EventFilter get Name,Query')
    results.append("=== WMI Event Filters ===")
    results.append(filters)

    # Check WMI event consumers (command line)
    consumers = run_cmd('wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer get Name,CommandLineTemplate')
    results.append("\n=== WMI Command Line Consumers ===")
    results.append(consumers if consumers.strip() else "No command line consumers")

    # Check WMI event consumers (script)
    script_consumers = run_cmd('wmic /namespace:\\\\root\\subscription path ActiveScriptEventConsumer get Name,ScriptText')
    results.append("\n=== WMI Script Consumers ===")
    results.append(script_consumers if script_consumers.strip() else "No script consumers")

    # Check WMI bindings
    bindings = run_cmd('wmic /namespace:\\\\root\\subscription path __FilterToConsumerBinding get Filter,Consumer')
    results.append("\n=== WMI Filter to Consumer Bindings ===")
    results.append(bindings)

    # Analyze for suspicious
    all_wmi = filters + consumers + script_consumers + bindings
    suspicious = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in all_wmi.lower():
            suspicious.append(f"Suspicious WMI: {kw}")
    if suspicious:
        results.append("\n=== SUSPICIOUS WMI ===")
        results.extend(suspicious)
    else:
        results.append("\nNo suspicious WMI persistence found")

    return '\n'.join(results)


# ============ Main ============

def main():
    print("=" * 60)
    print("BootVerify - Boot Sector Insurance Verification")
    print("Verifies MBR, EFI, and WMI persistence")
    print("=" * 60)

    # Check admin privileges
    admin, priv_type = is_admin()
    if not admin:
        print("\n[ERROR] Insufficient privileges!")
        print("Please run as Administrator or SYSTEM.")
        input("Press Enter to exit...")
        return
    print(f"\n[OK] Running with {priv_type} privileges")

    # Open report file
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"BootVerify Report\nTime: {now()}\n")
        f.write(f"System: {os.environ.get('COMPUTERNAME', 'Unknown')}\n")

        # 1. MBR
        print("\n[1/3] Verifying MBR...")
        mbr_result = verify_mbr()
        print(mbr_result)
        log_write(f, "1. MBR Verification", mbr_result)

        # 2. EFI
        print("\n[2/3] Verifying EFI...")
        efi_result = verify_efi()
        print(efi_result[:2000])
        log_write(f, "2. EFI Verification", efi_result)

        # 3. WMI
        print("\n[3/3] Verifying WMI...")
        wmi_result = verify_wmi()
        print(wmi_result[:2000])
        log_write(f, "3. WMI Verification", wmi_result)

        f.write(f"\n{'='*60}\nVerification Complete: {now()}\n")

    print(f"\nReport saved: {REPORT_FILE}")
    print("\nVerification complete!")
    input("Press Enter to exit...")


if __name__ == '__main__':
    main()
