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
