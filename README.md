# toolScanner-RassadV0.5 soon version 0.6 gonna be available
Powerful async network scanner with GUI — discover open ports, banners, and TLS info safely. ⚠️ Educational and ethical use only.

# Analyzer PRO — BY VO@TREX6 (GUI port / service scanner)

<p align="center">
  <img src="assets/2785025.png" alt="Analyzer PRO Logo" width="200"/>
</p>


**⚠️ Legal & Ethical Notice — READ FIRST**  
This project is provided **for educational and research purposes only**. Do **not** use this software to scan, probe, or test networks or systems for which you do not have **explicit written permission** to perform security testing. Unauthorized scanning may be illegal and could result in criminal or civil liability. By using or contributing to this project you agree to operate it only on systems you own or where you have explicit authorization. The author and repository maintainers are **not responsible** for any misuse.

> I am not a lawyer — this notice is intended to reduce risk and inform users. If you expect others to run this tool in production or at scale, consult legal counsel or your organization's security/compliance team.

--

## Overview
**Analyzer PRO** is an advanced single-file GUI port and service scanner written in Python. It supports asynchronous scanning, multi-target expansion (CIDR/ranges), optional UDP/TLS probes, autosave/resume, and JSON/CSV export. The GUI uses PyQt5 when available, with a Tkinter fallback.

## Key Features
- GUI: PyQt5 with Tkinter fallback.
- Async scanning core (asyncio) running inside a background thread.
- TCP connect banner grabbing (non-SYN).
- Optional UDP probing (executor-backed for reliability).
- Optional TLS certificate probing (blocking TLS fetch run in executor).
- Targets support: single IPs, comma lists, CIDR, ranges.
- Autosave/resume of partial scan state.
- Save/export results to JSON (and easily extendable to CSV).
- Concurrency/timeout controls, optional ping-before-scan.
- Simple banner fingerprinting rules.

<p align="center">
  <img src="assets/Screenshot 2025-11-13 145759.png" alt="Analyzer PRO GUI" width="800"/>
</p>


## Warnings & Limitations
- **Do not** scan systems or networks without explicit authorization.
- This tool uses TCP connect and simple UDP probes — it is **not** a stealthy or SYN-based scanner.
- UDP scans rely on timeouts and may be slow/unreliable for large ranges.
- TLS probing connects to the service and fetches certificates; avoid probing sensitive services without permission.
- This is **not** a replacement for professional tooling (e.g., `nmap`) for advanced auditing — consider it educational and practical for controlled environments.

## Requirements
- Python 3.8+ recommended (works with 3.7 in many cases).
- Optional (for full GUI): `PyQt5`
- Optional extras: `colorama` (console color), any other libs you add later.

Example `requirements.txt` is provided.

## Installation
1. Clone or download this repository.
2. (Optional) Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate    # Linux / macOS
   venv\Scripts\activate       # Windows (PowerShell)
