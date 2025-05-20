#!/bin/bash
# ===========================================================================
# FirmExtract Setup Script
# Author: Based on Gabriel Adams' FirmExtract tool
#
# This script installs all the necessary dependencies for the FirmExtract
# firmware analysis tool, including:
# - Python dependencies
# - Binwalk (firmware extraction)
# - Syft (SBOM generation)
# - Grype (vulnerability scanning)
# - Checksec (binary security checking)
# - OpenSSL (for certificate generation)
# ===========================================================================

# Text formatting
BOLD="\e[1m"
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"

# Function to print status messages
print_status() {
    echo -e "${BOLD}[+] ${1}${RESET}"
}

print_warning() {
    echo -e "${BOLD}${YELLOW}[!] ${1}${RESET}"
}

print_error() {
    echo -e "${BOLD}${RED}[-] ${1}${RESET}"
}

print_success() {
    echo -e "${BOLD}${GREEN}[✓] ${1}${RESET}"
}

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    print_warning "This script might need elevated privileges to install system packages."
    print_warning "Consider running with sudo if you encounter permission errors."
    echo ""
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
elif type lsb_release >/dev/null 2>&1; then
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
else
    OS=$(uname -s)
    VER=$(uname -r)
fi

print_status "Detected OS: $OS $VER"

# Install required packages based on OS
install_system_packages() {
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]] || [[ "$OS" == *"Kali"* ]]; then
        print_status "Installing system dependencies..."
        apt-get update
        apt-get install -y python3 python3-pip file binwalk openssl curl
        if [ $? -ne 0 ]; then
            print_error "Failed to install system packages. Try running with sudo."
            exit 1
        fi
    elif [[ "$OS" == *"Fedora"* ]] || [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]]; then
        print_status "Installing system dependencies..."
        dnf install -y python3 python3-pip file binwalk openssl curl
        if [ $? -ne 0 ]; then
            print_error "Failed to install system packages. Try running with sudo."
            exit 1
        fi
    elif [[ "$OS" == *"Arch"* ]] || [[ "$OS" == *"Manjaro"* ]]; then
        print_status "Installing system dependencies..."
        pacman -Sy python python-pip file binwalk openssl curl
        if [ $? -ne 0 ]; then
            print_error "Failed to install system packages. Try running with sudo."
            exit 1
        fi
    elif [[ "$OS" == *"Darwin"* ]] || [[ "$OS" == *"macOS"* ]]; then
        print_status "macOS detected. Installing dependencies with Homebrew..."
        if ! command -v brew &> /dev/null; then
            print_warning "Homebrew not found. Please install Homebrew first: https://brew.sh/"
            exit 1
        fi
        brew install python3 binwalk openssl curl
        if [ $? -ne 0 ]; then
            print_error "Failed to install brew packages."
            exit 1
        fi
    else
        print_warning "Unsupported OS detected: $OS"
        print_warning "Please manually install: python3, pip, file, binwalk, openssl, curl"
        print_warning "Then run this script again."
        exit 1
    fi
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        print_error "Failed to install Python dependencies."
        exit 1
    fi
    print_success "Python dependencies installed successfully!"
}

# Install Binwalk if not available or update it
install_binwalk() {
    if ! command -v binwalk &> /dev/null; then
        print_status "Binwalk not found. Installing..."
        if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]] || [[ "$OS" == *"Kali"* ]]; then
            apt-get install -y binwalk
        else
            pip3 install binwalk
        fi
        
        if [ $? -ne 0 ]; then
            print_error "Failed to install Binwalk."
            print_warning "You may need to install it manually: https://github.com/ReFirmLabs/binwalk"
        else
            print_success "Binwalk installed successfully!"
        fi
    else
        print_success "Binwalk is already installed!"
    fi
}

# Install Syft
install_syft() {
    print_status "Installing Syft..."
    if ! command -v syft &> /dev/null; then
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
        if [ $? -ne 0 ]; then
            print_error "Failed to install Syft."
            print_warning "You may need to install it manually: https://github.com/anchore/syft"
            exit 1
        fi
        print_success "Syft installed successfully!"
    else
        print_success "Syft is already installed!"
    fi
}

# Install Grype
install_grype() {
    print_status "Installing Grype..."
    if ! command -v grype &> /dev/null; then
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
        if [ $? -ne 0 ]; then
            print_error "Failed to install Grype."
            print_warning "You may need to install it manually: https://github.com/anchore/grype"
            exit 1
        fi
        print_success "Grype installed successfully!"
    else
        print_success "Grype is already installed!"
    fi
}

# Install Checksec
install_checksec() {
    print_status "Installing Checksec..."
    if ! command -v checksec &> /dev/null; then
        if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]] || [[ "$OS" == *"Kali"* ]]; then
            apt-get install -y checksec
            if [ $? -ne 0 ]; then
                print_warning "Could not install checksec from repositories. Trying from GitHub..."
                TEMP_DIR=$(mktemp -d)
                git clone https://github.com/slimm609/checksec.sh.git "$TEMP_DIR"
                cd "$TEMP_DIR"
                chmod +x checksec
                cp checksec /usr/local/bin/
                cd -
                rm -rf "$TEMP_DIR"
            fi
        else
            TEMP_DIR=$(mktemp -d)
            git clone https://github.com/slimm609/checksec.sh.git "$TEMP_DIR"
            cd "$TEMP_DIR"
            chmod +x checksec
            cp checksec /usr/local/bin/
            cd -
            rm -rf "$TEMP_DIR"
        fi
        
        if ! command -v checksec &> /dev/null; then
            print_error "Failed to install Checksec."
            print_warning "You may need to install it manually: https://github.com/slimm609/checksec.sh"
            exit 1
        fi
        print_success "Checksec installed successfully!"
    else
        print_success "Checksec is already installed!"
    fi
}

# Make firmware_analyzer.py executable
make_executable() {
    print_status "Making the firmware analyzer executable..."
    chmod +x firmware_analyzer.py
    print_success "Script is now executable!"
}

# Main installation process
main() {
    print_status "Starting FirmExtract installation..."
    
    install_system_packages
    install_python_deps
    install_binwalk
    install_syft
    install_grype
    install_checksec
    make_executable
    
    print_success "FirmExtract setup complete!"
    print_status "You can now use the tool with: ./firmware_analyzer.py [firmware_file]"
}

# Execute the main function
main