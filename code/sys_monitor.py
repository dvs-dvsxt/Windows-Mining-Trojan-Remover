# -*- coding: utf-8 -*-
"""
持续系统安全监控程序 v2
从启动开始持续监控系统，直到 C:\f.ini 被删除 或 运行满 3 分钟
监控服务、计划任务、自启动、进程、文件、网络、Windows安全中心等
"""
import os
import sys
import time
import subprocess
import datetime
import socket
import platform

# 结束条件文件
STOP_FILE = r"C:\f.ini"
# 最大运行时间（秒）
MAX_RUNTIME = 180  # 3 分钟

# 日志目录
LOG_DIR = r"C:\SysMonitorLogs"
os.makedirs(LOG_DIR, exist_ok=True)

# 已知恶意关键词
MALICIOUS_KEYWORDS = [
    'TfuSTvhb', 'YRbL1xSX', 'WpSJj0lv', 'RuntimeHost', 'RuntimeTask',
    '8B86CBC', '2FA7F989', 'ABE94A11', '15205438', 'D3F4E2A1', '50AB775E',
    'proxies-peer', '15AB6CF5', 'B95EB893', '5ghAHv', 'jHkYtN', 'zQM241sm',
    'nAumBAO1', 'lw5ypO', 'P41H56Vb', 'WE93mndC', 'KxDQmm', 'ccv', 'mzcv',
    'lolMiner', 'SRBMiner', 'gminer', 'miniZ', 'SecurityHealthHost',
    '0AzjkAEd', '6E7B6FD3', 'UT7ejTkn', 'ScreenConnect', 'Windows VC',
    'rasedy', 'Elevate Plans Interface', 'Windows System Health',
    'Workflow Contingency', 'Diagnostics.Client', 'SimpleRunPE'
]

# 挖矿矿池
MINING_POOLS = ['kryptex', '176.96.137.253', '217.216.109.4', '4041', 'rasedy.com', 'gleeze']


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


def collect_services():
    out = run_cmd('wmic service get name,displayname,state,startmode,pathname /format:csv')
    lines = [l for l in out.split('\n') if l.strip() and 'Node' not in l]
    result = []
    for l in lines[1:]:
        parts = l.strip().split(',')
        if len(parts) >= 6:
            name = parts[1].strip()
            state = parts[2].strip()
            start = parts[3].strip()
            path = parts[5].strip() if len(parts) > 5 else ''
            flag = ' <<< 可疑' if any(k.lower() in (name + path).lower() for k in MALICIOUS_KEYWORDS) else ''
            result.append(f"[{state}] {name} | Start={start} | {path}{flag}")
    return '\n'.join(result)


def collect_tasks():
    out = run_cmd('schtasks /query /fo csv /v')
    lines = [l for l in out.split('\n') if l.strip()]
    result = []
    for l in lines:
        flag = ' <<< 可疑' if any(k.lower() in l.lower() for k in MALICIOUS_KEYWORDS) else ''
        result.append(l.strip() + flag)
    return '\n'.join(result)


def collect_registry_run():
    result = []
    keys = [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    ]
    for k in keys:
        out = run_cmd(f'reg query "{k}"')
        flag = ' <<< 可疑' if any(m.lower() in out.lower() for m in MALICIOUS_KEYWORDS) else ''
        result.append(f"--- {k} ---{flag}\n{out}")
    return '\n'.join(result)


def collect_startup_folders():
    result = []
    folders = [
        r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
    ]
    for f in folders:
        if os.path.exists(f):
            files = os.listdir(f)
            result.append(f"--- {f} ---\n" + '\n'.join(files))
    return '\n'.join(result)


def collect_processes():
    out = run_cmd('wmic process get name,processid,parentprocessid,executablepath /format:csv')
    lines = [l for l in out.split('\n') if l.strip() and 'Node' not in l]
    result = []
    for l in lines[1:]:
        parts = l.strip().split(',')
        if len(parts) >= 5:
            name = parts[1].strip()
            pid = parts[2].strip()
            ppid = parts[3].strip()
            path = parts[4].strip()
            flag = ' <<< 可疑' if any(k.lower() in (name + path).lower() for k in MALICIOUS_KEYWORDS) else ''
            if flag or name in ['RuntimeHost.exe', 'RuntimeTask.exe', 'SecurityHealthHost.exe',
                                'ScreenConnect.ClientService.exe', 'ScreenConnect.WindowsClient.exe']:
                result.append(f"[{pid}] {name} | PPID={ppid} | {path}{flag}")
    return '\n'.join(result)


def collect_suspicious_files():
    result = []
    base_dirs = [
        r'C:\ProgramData',
        r'C:\Users\Public',
        r'C:\Program Files (x86)',
        r'C:\ProgramData\Microsoft\Windows\Caches',
    ]
    for base in base_dirs:
        if not os.path.exists(base):
            continue
        try:
            for root, dirs, files in os.walk(base):
                depth = root[len(base):].count(os.sep)
                if depth > 3:
                    dirs[:] = []
                    continue
                for item in dirs + files:
                    full = os.path.join(root, item)
                    if any(k.lower() in (item + full).lower() for k in MALICIOUS_KEYWORDS):
                        result.append(f"可疑: {full}")
        except Exception:
            pass
    return '\n'.join(result) if result else "未发现已知恶意文件"


def collect_network():
    out = run_cmd('netstat -ano')
    result = []
    for l in out.split('\n'):
        if any(p in l for p in MINING_POOLS):
            result.append(l.strip())
    return '\n'.join(result) if result else "未发现可疑网络连接"


def collect_defender_full():
    """Windows 安全中心完整检测"""
    result = []
    # 1. Defender 服务状态
    for svc in ['WinDefend', 'SecurityHealthService', 'wscsvc', 'MDCoreSvc', 'WdNisSvc']:
        out = run_cmd(f'sc query {svc}')
        state = 'RUNNING' if 'RUNNING' in out else 'STOPPED'
        result.append(f"{svc}: {state}")

    # 2. Defender 引擎状态
    out = run_cmd('powershell -NoProfile -Command "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; if ($s) { Write-Output (\'AV: \' + $s.AntivirusEnabled); Write-Output (\'RTP: \' + $s.RealTimeProtectionEnabled); Write-Output (\'SigVer: \' + $s.AntivirusSignatureVersion); Write-Output (\'EngineVer: \' + $s.AMEngineVersion); Write-Output (\'Tamper: \' + $s.IsTamperProtected); Write-Output (\'FullScanEnd: \' + $s.FullScanEndTime); Write-Output (\'QuickScanEnd: \' + $s.QuickScanEndTime) } else { Write-Output \'无法获取Defender状态\' }"')
    result.append("--- Defender 引擎状态 ---")
    result.append(out)

    # 3. Defender 排除项检测
    result.append("--- Defender 排除项 ---")
    out2 = run_cmd('powershell -NoProfile -Command "$p = Get-MpPreference -ErrorAction SilentlyContinue; Write-Output (\'Path: \' + ($p.ExclusionPath -join \', \')); Write-Output (\'Process: \' + ($p.ExclusionProcess -join \', \')); Write-Output (\'Extension: \' + ($p.ExclusionExtension -join \', \'))"')
    flag = ' <<< 可疑排除项' if any(k.lower() in out2.lower() for k in MALICIOUS_KEYWORDS) else ''
    result.append(out2 + flag)

    # 4. Defender 筛选器驱动
    result.append("--- Defender 驱动 ---")
    out3 = run_cmd('driverquery /v /fo csv 2>nul | findstr /i "WdFilter WdBoot WdNisDrv MsSecFlt"')
    result.append(out3)

    # 5. 最近引擎崩溃事件
    result.append("--- 最近引擎崩溃事件 ---")
    out4 = run_cmd('powershell -NoProfile -Command "Get-WinEvent -LogName \'Microsoft-Windows-Windows Defender/Operational\' -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object {$_.Id -eq 5008 -or $_.Id -eq 3002} | ForEach-Object { Write-Output ($_.TimeCreated.ToString() + \' | ID=\' + $_.Id + \' | \' + $_.Message.Substring(0, [Math]::Min(100, $_.Message.Length))) }"')
    result.append(out4 if out4.strip() else "无引擎崩溃事件")

    # 6. WDAC 策略检查
    result.append("--- WDAC 策略 ---")
    if os.path.exists(r'C:\Windows\System32\CodeIntegrity\SiPolicy.p7b'):
        result.append("SiPolicy.p7b 存在 (可疑)")
    else:
        result.append("SiPolicy.p7b 已删除 (正常)")

    return '\n'.join(result)


def collect_lsa_authpackages():
    out = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v "Authentication Packages"')
    flag = ' <<< 可疑' if any(k.lower() in out.lower() for k in MALICIOUS_KEYWORDS) else ''
    return out + flag


def collect_services_registry():
    out = run_cmd('wmic service get name,pathname /format:csv')
    result = []
    for l in out.split('\n'):
        if any(k.lower() in l.lower() for k in MALICIOUS_KEYWORDS):
            result.append(l.strip())
    return '\n'.join(result) if result else "服务注册表中未发现可疑路径"


def snapshot(f, round_num, elapsed):
    log_write(f, f"快照 #{round_num} (运行 {elapsed:.0f} 秒)", "")
    log_write(f, "1. 所有系统服务", collect_services())
    log_write(f, "2. 所有计划任务", collect_tasks())
    log_write(f, "3. 注册表自启动项", collect_registry_run())
    log_write(f, "4. 启动文件夹", collect_startup_folders())
    log_write(f, "5. 可疑进程", collect_processes())
    log_write(f, "6. 可疑文件扫描", collect_suspicious_files())
    log_write(f, "7. 网络连接", collect_network())
    log_write(f, "8. Windows安全中心完整检测", collect_defender_full())
    log_write(f, "9. LSA认证包", collect_lsa_authpackages())
    log_write(f, "10. 服务注册表可疑路径", collect_services_registry())


def main():
    start_time = time.time()
    log_file = os.path.join(LOG_DIR, f'continuous_monitor_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(f"持续系统安全监控日志 v2\n开始时间: {now()}\n")
        f.write(f"主机名: {socket.gethostname()}\n")
        f.write(f"系统: {platform.platform()}\n")
        f.write(f"停止条件: {STOP_FILE} 被删除 或 运行 {MAX_RUNTIME} 秒\n")
        f.write(f"采样间隔: 5 秒\n")
        f.flush()

        round_num = 0
        while True:
            elapsed = time.time() - start_time

            stop_reason = None
            if not os.path.exists(STOP_FILE):
                stop_reason = f"停止文件 {STOP_FILE} 已被删除"
            elif elapsed >= MAX_RUNTIME:
                stop_reason = f"运行时间达到 {MAX_RUNTIME} 秒"

            round_num += 1
            snapshot(f, round_num, elapsed)

            if stop_reason:
                log_write(f, "停止", f"停止原因: {stop_reason}")
                break

            time.sleep(5)

        f.write(f"\n{'='*60}\n监控结束: {now()}\n总采样次数: {round_num}\n")

    print(f"监控日志已写入: {log_file}")


if __name__ == '__main__':
    main()
