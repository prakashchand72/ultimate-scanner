# Ultimate Scanner

**Aggressive Red Team & Bug Bounty Scanner** — A single-target vulnerability discovery and exploitation framework that chains together multiple security tools for in-depth reconnaissance, enumeration, and exploitation.  

⚠ **Warning:** This scanner is **very aggressive** and contains **exploit modules**.  
Use **only** with **explicit written authorization**. Unauthorized usage is illegal.

---

## 📌 Features
- **Automated setup** via `setup.sh` for installing all required tools
- **Aggressive scanning** with `ultimate_vuln_scan_mega.sh`
- Integrates multiple recon and exploitation tools
- Supports authenticated testing via cookies
- Multi-threaded scanning
- Optional **non-exploit mode** for safer recon
- Generates organized scan results in a dedicated folder

---

## 📂 installation
# Clone the repository
```sh
git clone https://github.com/prakashchand72/ultimate-scanner.git
cd ultimate-scanner
```
# Install all dependencies
```sh
chmod +x setup.sh
./setup.sh
chmod +x ultimate_vuln_scan_mega.sh
```
# usage
Run a full aggressive scan with exploitation
```sh
./ultimate_vuln_scan_mega.sh --url https://target.com --threads 150
```
Run a safe scan without exploitation
```sh
./ultimate_vuln_scan_mega.sh --url https://target.com --no-exploit
```
Scan with authentication
```sh
./ultimate_vuln_scan_mega.sh --url https://target.com --auth-cookie "SESSIONID=abc123"
```
Custom output directory
```sh
./ultimate_vuln_scan_mega.sh --url https://target.com --output /path/to/reports
```
# 📁 Output Structure
```sh
scan_results/
└── YYYY-MM-DD_HH-MM-SS/
    ├── nmap.txt         # Port scan results
    ├── urls.txt         # Collected URLs/endpoints
    ├── other_tool.txt   # Output from other tools
    └── ...
```
