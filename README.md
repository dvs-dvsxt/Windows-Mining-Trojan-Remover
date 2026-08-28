# 🛡️ Windows Mining Trojan Remover (WMTR)

> A one-click **mining trojan removal toolkit** for Windows. Scans, detects, and removes cryptocurrency mining malware, restores registry integrity, and verifies boot-sector persistence.

**Windows Mining Trojan Remover (WMTR)** is a comprehensive toolkit designed to detect and eliminate mining trojans, remote-control backdoors, and boot-sector persistence on Windows systems. It combines multiple scan engines — file, registry, scheduled tasks, processes, network, and boot verification — into one streamlined workflow.

> **⚠️ IMPORTANT**: This tool performs privileged system operations (killing processes, deleting files, modifying registry, boot-sector verification). **Run as Administrator or SYSTEM.** Use at your own risk.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🗂️ **File Scan** | Scans key folders (`ProgramData`, `Public`, `Program Files`, `Temp`) for malicious files |
| 🔑 **Registry Scan** | Detects suspicious startup entries & restores Windows Defender exclusions |
| ⏰ **Scheduled Task Scan** | Detects malicious scheduled tasks (including English-word deception) |
| ⚙️ **Process Scan** | Identifies and kills malicious processes (`Get-Process`, no deprecated `wmic`) |
| 🌐 **Network Scan** | Flags connections to known mining pools / C2 servers |
| 🔤 **Random-Name Checker** | Detects virus-like random filenames |
| ♻️ **Post-Restart Compare** | Compares logs after reboot to detect old/new viruses |
| 🧹 **Auto-Cleanup** | Removes autostart when system is confirmed clean |
| 💾 **Scan Logs** | Saves detailed scan & cleanup records to `C:\SysMonitorLogs` |
| 🔒 **Privilege Check** | Verifies ADMIN / NT / SYSTEM privileges before running |

### Boot Verification (BootVerify)
- 🔎 Verifies **MBR**, **EFI**, and **WMI** persistence for trojan infection
- Uses Python libraries, system tools, and `BOOTICE.exe`

---

## ✅ v1.0.1 Fixes

This release fixes several issues found in v1.0.0:

| Fix | Description |
|-----|-------------|
| 🟢 **AweSun False Positive** | Removed AweSun (Sunlogin remote control) from malicious keywords; added to whitelist |
| 🔧 **Process Scan Overhaul** | Replaced deprecated `wmic` with PowerShell `Get-Process` (removed on Win 10/11) |
| 🗑️ **Effective Deletion/Kill** | Fixed `_found_malicious_files` / `_found_malicious_processes` not being passed — now uses global variables |
| 📁 **Path Fix** | `WORK_DIR` now uses script directory (`os.path.dirname(os.path.abspath(__file__))`) instead of hardcoded path |
| 📝 **Expanded Whitelist** | Added AweSun, Thunder, PalmInput, Wujie, CrystalDisk, and system processes to avoid false positives |
| 🚫 **Path Whitelist** | Skips scanning legitimate dirs (AweSun, CrystalDisk, Thunder, PalmInput, Wujie) |
| 🔇 **Silent Errors** | Added `2>nul` to reg/schtasks commands to suppress "path not found" errors |
| 🔍 **Registry Scan Fix** | Only outputs suspicious registry items (no more repeated spam) |
| 🎲 **Random-Name Tuning** | Only checks `.exe/.dll/.dat/.tmp/.sys/.bin`; whitelisted names not flagged |

---

## 🚀 Quick Start

### Prerequisites
- Windows 7 / 8 / 10 / 11
- **Administrator privileges** (right-click → *Run as administrator*)

### Run (Compiled EXE)

```powershell
# Run main cleanup tool (as administrator)
WMTR_MAIN.exe

# Run system monitor
sys_monitor.exe

# Run boot verification
BootVerify.exe
```

### Run from Source (Python)

```powershell
# Requires Python 3.x
python code/WMTR.py
python code/sys_monitor.py
python code/BootVerify.py
```

### Rebuild the EXE

```powershell
# Rebuild WMTR_MAIN.exe from source
cd code
pyinstaller --onefile --name WMTR_MAIN --console WMTR.py
```

---

## 📦 Project Structure

```
Windows-Mining-Trojan-Remover/
├── code/                # Python source code
│   ├── WMTR.py          # Main mining trojan remover
│   ├── sys_monitor.py   # Continuous system monitor
│   ├── BootVerify.py    # Boot sector verification
│   └── BOOTICE.exe      # Boot sector management tool
├── WMTR_MAIN.exe        # Compiled main cleanup tool
├── sys_monitor.exe      # Compiled system monitor
├── BootVerify.exe       # Compiled boot verification
├── BOOTICE.exe          # Boot sector management tool
└── README.md            # This document
```

---

## 🔧 How It Works

1. **Scan** — Scans files, registry, scheduled tasks, processes, and network for malicious indicators (known mining keywords + dynamic startup-keyword extraction)
2. **Cleanup** — Kills malicious processes, deletes malicious files, restores registry & security software
3. **Autostart** — Sets up `sys_monitor` and `WMTR` autostart to continue monitoring after reboot
4. **Compare** — After restart, compares logs to detect old/new viruses
5. **Auto-remove** — Removes autostart when system is confirmed clean

### Detection Coverage
- **Mining trojans**: lolMiner, SRBMiner, gminer, miniZ, UT7ejTkn, RuntimeHost, etc.
- **Remote control**: ScreenConnect, ConnectWise, rasedy, Windows VC
- **Mining pools / C2**: kryptex, gleeze, 176.96.137.253, etc.
- **English-word deception**: fake task names like "Efficiently Achieve Analysis", "Windows System Health"

### Whitelist (to avoid false positives)
- AweSun / AweSun Guard (Sunlogin)
- Thunder (迅雷), PalmInput (手心输入法), Wujie (无界浏览器)
- CrystalDiskInfo / CrystalDiskMark
- Common system processes (svchost, lsass, winlogon, etc.)

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 🙏 Disclaimer

> This tool modifies system-critical components (registry, startup, boot sector). **Use at your own risk.** Always back up important data and disable antivirus tamper protection if prompted. The authors are not responsible for any system damage or data loss.
