# Enum-Vuln-Drivers

**Enumerating vulnerable drivers in Windows to detect potential security risks.**  
This tool scans loaded drivers and checks them against a list of known vulnerable modules.

## 🚀 Features
- Enumerates loaded kernel drivers.
- Cross-checks driver names against a provided vulnerability list (`drv.txt`).
- Flags drivers that may pose security risks.

## Usage:
./evd.exe <list>
