#!/usr/bin/env python3
# =============================================================================
# Firmware Security Analysis Tool
#
# Author: Gabriel Adams
# Note from author: 
#   This is a tool that is created to streamline the vulnerability research 
#   process of IoT devices. I noticed I was running a lot of the same commands 
#   every time I was assessing new firmware, so I decided to combine a lot of them
#   into a single script. I do not take credit for the amazing library's used within
#   the script, as they are simply tools that I often take advantage of. Any
#   suggestion for improvements are welcome, and I hope You enjoy FirmExtract!
#   
#
# A comprehensive tool for firmware security assessment that:
# - Extracts firmware contents
# - Generates SBOMs (Software Bill of Materials)
# - Detects vulnerabilities (CVEs)
# - Finds credentials and cryptographic keys
# - Analyzes binary security protections
# - Checks for CA certificate injection possibilities (rudementary checks)


# NOTICE: If the script does not catch any of the aformentioned keys, certs, creds, or vulns, 
#   you should still look through the firmware manually. I am making no guarentee that the tool
#   catches 100% of the desired artifacts. 

# =============================================================================

import argparse
import os
import subprocess
import json
from pathlib import Path
from datetime import datetime, timezone
import re

# List of common certificate file names found in embedded systems
# These are typical extensions where CA certificates might be stored
CERT_FILE_EXTENSIONS = ('.crt', '.pem')

def extract_firmware(firmware_path):
    """
    Extract the firmware contents using binwalk.
    
    Binwalk (https://github.com/ReFirmLabs/binwalk) is a tool for analyzing, 
    reverse engineering, and extracting firmware images. Here we use it to 
    extract the contents from the firmware file.
    
    Args:
        firmware_path: Path to the firmware binary file
        
    Returns:
        Path to the extracted directory
    """
    # Run binwalk with root privileges to extract the firmware
    subprocess.run(["binwalk", "--run-as=root", "-e", firmware_path], check=True)
    
    # binwalk creates directories with names like "_firmware.bin.extracted"
    extract_dirs = sorted(Path(".").glob(f"_{Path(firmware_path).name}*.extracted"))
    if not extract_dirs:
        raise FileNotFoundError("No extracted firmware directory found.")
    return extract_dirs[0]

def generate_sbom(extract_dir):
    """
    Generate a Software Bill of Materials (SBOM) using Syft.
    
    Syft (https://github.com/anchore/syft) is a tool for generating SBOMs from 
    containers and filesystems. It identifies packages and dependencies by 
    analyzing the extracted firmware contents. I am using it to create one large file 
    to later analyze for a deeper dependency analysis. 
    
    Args:
        extract_dir: Directory containing the extracted firmware
        
    Returns:
        Path to the generated SBOM JSON file
    """
    sbom_path = Path("sbom.json")
    with open(sbom_path, "w") as f:
        # syft [directory] -o json -q
        subprocess.run(["syft", f"dir:{extract_dir}", "-o", "json", "-q"], check=True, stdout=f)
    return sbom_path

def scan_vulnerabilities(sbom_path):
    """
    Scanning for KNOWN vulnerabilities using Grype on the generated SBOM.
    
    Grype (https://github.com/anchore/grype) is a vulnerability scanner that 
    works with SBOMs. It compares the detected packages against vulnerability 
    databases to identify known security issues.

    I am using the above created sbom file to find known vulnerabilities
    
    Args:
        sbom_path: Path to the SBOM JSON file
        
    Returns:
        Dictionary containing vulnerability information
    """
    # Run grype on the SBOM to identify vulnerabilities
    grype_output = subprocess.run(
        ["grype", f"sbom:{sbom_path}", "-o", "json"],
        capture_output=True, text=True
    )
    return json.loads(grype_output.stdout)

def split_certificates(decoded_cert_data, file_path):
    """
    Split a file containing multiple certificates into individual certificate objects.
    
    Certificate files often contain multiple PEM-encoded certificates. This function
    separates them into individual certificate objects for easier analysis.
    
    Args:
        decoded_cert_data: String containing certificate data
        file_path: Path to the original certificate file
        
    Returns:
        List of certificate objects
    """
    certs = []
    current_cert = []
    lines = decoded_cert_data.splitlines()
    
    # Process line by line to extract individual certificates
    for line in lines:
        if "BEGIN CERTIFICATE" in line:
            # Start of a new certificate
            current_cert = [line]
        elif "END CERTIFICATE" in line:
            # End of current certificate
            current_cert.append(line)
            certs.append({
                "path": file_path,
                "type": "CERT",
                "data": "\n".join(current_cert)
            })
            current_cert = []
        elif current_cert:
            # Part of the current certificate
            current_cert.append(line)
    return certs

def find_credentials_and_keys(extract_dir):
    """
    Searching for credentials and cryptographic keys in the extracted firmware.
    
    This function scans for various types of security-sensitive materials:
    - Username/password entries (like those in /etc/shadow or /etc/passwd)
    - SSH keys (public and private)
    - TLS certificates
    - Other public and private keys
    
    Args:
        extract_dir: Directory containing the extracted firmware
        
    Returns:
        Dictionary containing found credentials and keys
    """
    findings = {
        "credentials": [],
        "ssh_keys": [],
        "tls_certificates": [],
        "public_keys": [],
        "private_keys": []
    }

    # Regex for shadow/passwd-style lines: username:$type$salt$hash:...
    # This pattern matches Linux password entries commonly found in /etc/shadow or /etc/passwd
    credential_pattern = re.compile(r"^[a-zA-Z0-9_-]+:[^:]*:")

    # Walk through all files in the extracted directory
    for root, _, files in os.walk(extract_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "rb") as f:
                    content = f.read()

                try:
                    # Try to decode as UTF-8; skip if binary
                    decoded = content.decode("utf-8")
                except UnicodeDecodeError:
                    continue

                # Check for private keys (PEM-encoded)
                if "PRIVATE KEY" in decoded:
                    findings["private_keys"].append({
                        "path": file_path,
                        "data": decoded.strip()
                    })

                # Check for public keys (PEM-encoded or SSH format)
                if "PUBLIC KEY" in decoded or "ssh-rsa" in decoded:
                    findings["public_keys"].append({
                        "path": file_path,
                        "data": decoded.strip()
                    })

                # Check for TLS certificates
                if "BEGIN CERTIFICATE" in decoded:
                    findings["tls_certificates"].extend(
                        split_certificates(decoded, file_path)
                    )

                # Check for SSH private keys (specifically RSA type)
                if "PRIVATE KEY" in decoded and "RSA" in decoded:
                    findings["ssh_keys"].append({
                        "path": str(file_path),
                        "type": "RSA",
                        "data": decoded.strip()
                    })

                # Check for credential entries using regex
                for line in decoded.splitlines():
                    if credential_pattern.match(line):
                        findings["credentials"].append({
                            "path": str(file_path),
                            "type": "shadow_or_passwd_entry",
                            "data": line.strip()
                        })

            except Exception:
                # Skip files that can't be processed
                continue

    return findings


def checksec_binaries(extract_dir):
    """
    Checking for ELF binaries for security protections using checksec.
    
    Checksec (https://github.com/slimm609/checksec.sh) is a tool that checks 
    Linux executable properties for security features like RELRO, Stack Canary,
    NX bit, PIE, etc.
    

    This can sometimes help me find out what I am working with on the device's security. 
    MOST IoT devices have minimal binary security features, but knowing when one does 
    can save time in the long run.

        Args:
        extract_dir: Directory containing the extracted firmware
        
    Returns:
        List of dictionaries with binary paths and their security features
    """
    binary_issues = []
    
    # Walk through all files in the extracted directory
    for root, _, files in os.walk(extract_dir):
        for file in files:
            path = os.path.join(root, file)
            try:
                # Use 'file' command to identify ELF binaries
                file_output = subprocess.check_output(["file", path], text=True)
                if "ELF" in file_output:
                    # For ELF binaries, run checksec to analyze security features
                    result = subprocess.run(
                        ["checksec", "analyze", "--file", path, "--format", "json"],
                        capture_output=True, text=True
                    )
                    output = json.loads(result.stdout)
                    binary_issues.append({"binary": str(path), "checksec": output})
            except:
                # Skip files that can't be analyzed
                continue
    return binary_issues

def save_json_report(data, path):
    """
    Save a JSON report to disk.
    
    Args:
        data: Data to save as JSON
        path: Path to save the report to
    """
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def save_artifacts_to_directory(data_list, directory, prefix):
    """
    Save multiple items to separate JSON files in a directory.
    
    Args:
        data_list: List of items to save
        directory: Directory to save to
        prefix: Prefix for file names
    """
    os.makedirs(directory, exist_ok=True)
    for i, item in enumerate(data_list):
        filename = os.path.join(directory, f"{prefix}_{i+1}.json")
        with open(filename, "w") as f:
            json.dump(item, f, indent=2)

def detect_ca_injection_possible(extract_dir):
    """
    Check if CA certificate injection is possible by looking for any .crt or .pem file.
    

    Sometimes I want to try and create a proxy to looks at web traffic of a device, but need 
        a cert to decrypt the traffic. If one is found then it will take it and the next function
        can create a root CA cert to be added and used to decrypt. 

    Args:
        extract_dir: Directory containing the extracted firmware
        
    Returns:
        List of paths to found certificate-like files
    """
    found_paths = []
    for root, _, files in os.walk(extract_dir):
        for name in files:
            if name.endswith(CERT_FILE_EXTENSIONS):
                found_paths.append(os.path.join(root, name))
    return found_paths

def generate_root_ca(cert_path="proxy-ca.pem", key_path="proxy-ca.key"):
    """

    Hello, I am 'next function'.


    Generate a root CA certificate and private key using OpenSSL.
    
    This creates a self-signed certificate that could be used for MITM attacks
    if injected into a device's trusted certificate store.
    
    Args:
        cert_path: Path to save the certificate to
        key_path: Path to save the private key to
    """

    
    # Generate a 2048-bit RSA key and self-signed certificate valid for 365 days
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "365",
                    "-nodes", "-keyout", key_path, "-out", cert_path,
                    "-subj", "/CN=FirmwareMITMCA"], check=True)
    print(f"\n[+] Root CA generated:")
    print(f" - Certificate: {cert_path}")
    print(f" - Private Key: {key_path}")

def uart_injection_instruction(cert_path, device_path="/etc/ssl/certs/ca-certificates.crt"):
    """

    This function works like half the time, but it's meant to give a quick and easy output to 
        get your generated cert added specifically if you have an active UART connection. 

    Display instructions for injecting a certificate via UART.
    
    UART (Universal Asynchronous Receiver/Transmitter) connections often provide 
    console access to embedded devices. This function provides a command to inject 
    a certificate using such a connection.
    
    Args:
        cert_path: Path to the certificate to inject
        device_path: Path on the target device where the certificate should be injected
    """
    print("\n[!] Use the following UART command to inject your certificate (after connecting via serial):")
    print("--------------------------------------------------------------------------")
    print(f"echo '{Path(cert_path).read_text()}' >> {device_path}")
    print("--------------------------------------------------------------------------")
    print("Then reboot the device or restart its networking service.\n")

def generate_report(firmware_path, extract_dir, vuln_data, creds_keys, binary_issues):
    """
    Generate a comprehensive report of all findings, and create the necessry directories
        for them to be viewed in. 
    
    This function organizes all the data collected during the analysis into a 
    structured report directory with separate files for different types of findings.
    
    Args:
        firmware_path: Path to the firmware binary
        extract_dir: Directory containing the extracted firmware
        vuln_data: Vulnerability data from Grype
        creds_keys: Credentials and keys found in the firmware
        binary_issues: Binary security issues found
    """
    report_root = Path("REPORT")
    report_root.mkdir(exist_ok=True)

    # Create a summary report with basic information
    summary = {
        "firmware": str(firmware_path),
        "extracted_path": str(extract_dir),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    save_json_report(summary, report_root / "summary.json")

    # Format vulnerability data
    cves = []
    for match in vuln_data.get("matches", []):
        cves.append({
            "package": match["artifact"]["name"],
            "version": match["artifact"]["version"],
            "cve": match["vulnerability"]["id"],
            "severity": match["vulnerability"]["severity"]
        })
    save_artifacts_to_directory(cves, report_root / "cves", "cve")

    # Save credentials and keys to their respective directories
    save_artifacts_to_directory(creds_keys["credentials"], report_root / "credentials", "cred")
    save_artifacts_to_directory(creds_keys["ssh_keys"], report_root / "ssh_keys", "ssh_key")
    save_artifacts_to_directory(creds_keys["tls_certificates"], report_root / "tls_certs/public", "cert")
    save_artifacts_to_directory(creds_keys["private_keys"], report_root / "tls_certs/private", "privkey")
    save_artifacts_to_directory(creds_keys["public_keys"], report_root / "tls_certs/public_keys", "pubkey")

    # Save binary security issues
    save_artifacts_to_directory(binary_issues, report_root / "binary_issues", "binary")

    print(f"\n[+] Reports saved under '{report_root}/'")
    for sub in ["summary.json", "cves", "credentials", "ssh_keys", "tls_certs", "binary_issues"]:
        print(f" - {sub}")

def main():
    """
    Main function that orchestrates the firmware analysis process.
    """
    # Set up command-line arguments
    parser = argparse.ArgumentParser(
        description="Static Firmware Vulnerability Scanner + Root CA Injection Checker"
    )
    parser.add_argument("firmware", help="Path to firmware binary")
    parser.add_argument("--no-cve", action="store_true", help="Skip CVE scanning")
    parser.add_argument("--no-creds", action="store_true", help="Skip credentials and keys scanning")
    parser.add_argument("--no-checksec", action="store_true", help="Skip ELF binary security checks")
    parser.add_argument("--skip-extract", action="store_true", help="Use pre-extracted firmware directory")
    args = parser.parse_args()

    firmware_path = args.firmware

    # Extract firmware or use pre-extracted directory
    if args.skip_extract:
        print("[+] Skipping extraction, using pre-extracted directory...")
        extract_dirs = sorted(Path(".").glob(f"_{Path(firmware_path).name}*.extracted"))
        if not extract_dirs:
            raise FileNotFoundError("No pre-extracted firmware directory found.")
        extract_dir = extract_dirs[0]
    else:
        print("[+] Extracting firmware...")
        extract_dir = extract_firmware(firmware_path)

    # Scan for CVEs if not disabled
    if not args.no_cve:
        print("[+] Generating SBOM and scanning for CVEs...")
        sbom_path = generate_sbom(extract_dir)
        vuln_data = scan_vulnerabilities(sbom_path)
    else:
        vuln_data = {}

    # Scan for credentials and keys if not disabled
    if not args.no_creds:
        print("[+] Scanning for credentials and keys...")
        creds_keys = find_credentials_and_keys(extract_dir)
    else:
        creds_keys = {"credentials": [], "ssh_keys": [], "tls_certificates": [],
                      "private_keys": [], "public_keys": []}

    # Check binary security if not disabled
    if not args.no_checksec:
        print("[+] Checking ELF binaries for missing protections...")
        binary_issues = checksec_binaries(extract_dir)
    else:
        binary_issues = []

    # Generate report with all findings
    generate_report(firmware_path, extract_dir, vuln_data, creds_keys, binary_issues)

    # Check for CA injection possibility
    print("[+] Checking for root CA injection possibility...")
    ca_files = detect_ca_injection_possible(extract_dir)
    if ca_files:
        print("[!] Potential certificate authority stores found:")
        for path in ca_files:
            print(f" - {path}")
        inject = input("\n[?] Would you like to generate a custom root CA and see the injection command? (y/N): ").strip().lower()
        if inject == "y":
            generate_root_ca()
            uart_injection_instruction("proxy-ca.pem", device_path=ca_files[0])
    else:
        print("[+] No standard CA files found. Injection may not be possible without patching firmware.")

if __name__ == "__main__":
    main()