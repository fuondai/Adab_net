# NT140.P11-NetworkScanner

Adabnet is a powerful network scanning tool that allows you to check, scan devices, services, subdomains, vulnerabilities, and much more on a network. This tool uses various scanning and analysis methods, including DNS scanning, MAC scanning, subdomain scanning, vulnerability scanning, and real-time network monitoring with Wireshark.

Key Features
Subdomain Scanning: Discover all subdomains of a given domain.
DNS Scanning: Check the DNS records of a domain.
Vulnerability Scanning: Scan for vulnerabilities using the Shodan API.
Traceroute: Trace the path of packets across the network.
Device Scanning: Find devices connected to your network.
Wireshark Integration: Monitor network packets in real-time with Wireshark.
Directory Busting: Use dirbuster to find hidden directories on websites.
API Key Management: Manage and encrypt your API key for enterprise features.
Project Structure
Here is the project structure of Adabnet:
NetworkScanner/
├── scanner/                          # 🛠️ Powerful scanning tools!
│   ├── __init__.py                   # 👷‍♂️ The starting point of the scanning journey!
│   ├── cli.py                        # 📡 Cute command-line arguments to run the tool
│   ├── core.py                       # 🧠 The brain of the project, contains core services like service scanning, ping, ARP
│   ├── dns_scanner.py                # 🌐 Expert in DNS scanning, finding every DNS record!
│   ├── specialized_scan.py           # 🔍 Specialized scans for adventurous types
│   ├── auth_scanner.py               # 🔐 Security scanning for authentication vulnerabilities
│   ├── mac_scanner.py                # 🖥️ Scan MAC addresses, know who's on your network
│   ├── thank_you.py                  # ❤️ Thank you for using this awesome tool!
│   ├── dirbuster.py                  # 🚪 Directory busting, find hidden paths in websites
│   ├── device_scanner.py             # 📱 Scan devices connected to your network
│   ├── subdomain_scanner.py          # 🏰 Scan subdomains of a domain, discover new territories
│   ├── vuln_scanner.py               # 🔥 Scan for vulnerabilities, don’t let them escape!
│   ├── whois_scanner.py              # 🕵️‍♂️ Whois information lookup
│   ├── traceroute_scanner.py         # 🌍 Trace the path of packets, from you to the world!
│   ├── wireshark_scanner.py          # 🐳 Monitor network traffic with Wireshark, explore every packet!
│   ├── license_manager.py            # 🛡️ API key management and encryption tools
│   └── utils.py                      # ⚙️ Utility functions to make everything easier
├── main.py                           # 🚀 The entry point of the scanning journey, let’s start!
├── requirements.txt                  # 📜 The necessary libraries to make everything work
├── license.key                       # 🔑 The secret API key file (don’t lose it!)
├── secret.key                        # 🔒 The secret key used for encryption/decryption
└── README.md                         # 📚 Documentation to guide you through everything (don’t skip it!)

Installation and System Requirements
System Requirements:
Python 3.6+
Required Libraries:
requests: For sending HTTP requests for API and vulnerability scanning.
python-whois: To retrieve WHOIS information.
pyshark: For network traffic monitoring using Wireshark.
colorama: For adding color to the terminal UI.
shodan: For vulnerability scanning with the Shodan API.
cryptography: For encrypting and decrypting the API key.
Install Required Libraries:
Install all the required libraries by running the following command:
pip install -r requirements.txt

Shodan API Setup:
You will need a Shodan API key to use the vulnerability scanning feature. You can get your API key by signing up at Shodan.

License and Key Setup:
License File: When you run the program for the first time with the enterprise feature, you will be asked to enter your API key, which will then be encrypted and saved in the license.key file.

How to Use
Activate Enterprise License:
If you do not have an enterprise license, the program will ask you to enter an API key:
python main.py --enterprise

Thank You and Contact
Thank you for using NetworkScanner! If you have any questions or would like to contribute to the project, feel free to contact us or create an issue on GitHub.

We are always happy to receive feedback and improve this tool to help you work more efficiently! 🚀

License
This project is licensed under the MIT License.

Enjoy scanning and have fun with NetworkScanner! 🎉
