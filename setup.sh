#!/bin/bash

# Check and install Python if not present
if ! command -v python3 &> /dev/null
then
    echo "Python3 is not installed. Installing Python3..."
    sudo apt update
    sudo apt install -y python3 python3-pip
fi

# Check and install pip if not present
if ! command -v pip3 &> /dev/null
then
    echo "pip is not installed. Installing pip..."
    sudo apt install -y python3-pip
fi

# Install the required libraries
echo "Installing Python libraries..."
pip3 install socket scapy ipaddress threading argparse prettytable nmap colorama requests cryptography ftplib telnetlib paramiko smtplib shodan whois pyshark

echo "Installation complete!"
