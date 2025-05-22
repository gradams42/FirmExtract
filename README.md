# FirmExtract: Firmware Security Analysis Tool

**Author**: Gabriel Adams  
**Description**: FirmExtract is a static analysis tool for IoT firmware images that automates extraction, vulnerability scanning, credential discovery, binary security checks, and CA injection testing.

---

## Overview

FirmExtract is designed to simplify and automate many of the repetitive tasks associated with firmware vulnerability research. It integrates powerful tools like `binwalk`, `syft`, `grype`, and `checksec` to streamline the workflow.

This tool performs the following:

- Extracts firmware contents using `binwalk`
- Generates a Software Bill of Materials (SBOM) using `syft`
- Detects known vulnerabilities (CVEs) via `grype`
- Finds hardcoded credentials, SSH keys, and cryptographic material
- Analyzes ELF binaries for security protections with `checksec`
- Identifies certificate files to assess CA injection potential
- Offers to generate a root CA and provides UART injection instructions

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/gradams42/FirmExtract.git
cd FirmExtract
````

### 2. Create and Activate a Python Virtual Environment

I recommend to use a virtual environment to avoid conflicts with system Python packages. 

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies

Install all required Python packages from the `requirements.txt` file:

```bash
pip install -r requirements.txt
```

### 4. Run the Setup Script

Run the included `setup.sh` script with superuser privileges to install and configure required system tools:

```bash
sudo ./setup.sh
```

> This script may install tools like `binwalk`, `syft`, `grype`, `checksec`, and other dependencies required for the tool to work.

---

## Usage

### Basic Command

```bash
sudo pthon3 FirmExtract.py firmware_file.bin
```

Running the tool with sudo is required for binwalk to access all possible data during extraction. 

Replace `firmware_file.bin` with the path to your firmware binary file.

### Parameters and Options

| Option           | Description                                                                |
| ---------------- | -------------------------------------------------------------------------- |
| `--skip-extract` | Use a pre-extracted firmware directory (skips the binwalk extraction step) |
| `--no-cve`       | Skip vulnerability scanning with `grype`                                   |
| `--no-creds`     | Skip scanning for credentials, keys, and certificates                      |
| `--no-checksec`  | Skip binary analysis using `checksec`                                      |

### Example Usage

**Full scan (default):**

```bash
sudo python3 FirmExtract.py firmware_file.bin
```

**Scan using already-extracted firmware:**

```bash
sudo python3 FirmExtract.py firmware_file.bin --skip-extract
```

**Scan without CVE detection:**

```bash
sudo python3 FirmExtract.py firmware_file.bin --no-cve
```

**Scan only for credentials and binary protections:**

```bash
sudo python3 FirmExtract.py firmware_file.bin --no-cve --skip-extract
```

---

## Output

All results will be saved in a structured directory named `REPORT/`:

```
REPORT/
├── summary.json
├── cves/
├── credentials/
├── ssh_keys/
├── tls_certs/
│   ├── public/
│   ├── private/
│   └── public_keys/
└── binary_issues/
```

Each directory contains individual JSON files detailing the findings in that category.

---

## Root CA Injection

If `.crt` or `.pem` certificate files are found in the firmware:

* The tool will offer to generate a self-signed root certificate (`proxy-ca.pem`) and private key (`proxy-ca.key`)
* It will then display UART-based instructions to inject the certificate into the firmware's trusted CA store

This is useful for setting up man-in-the-middle (MITM) testing environments.


## Notes

* Manual review of firmware is still necessary. I do not guarantee full coverage.
* Suggestions, bug reports, and contributions are welcome.

---
