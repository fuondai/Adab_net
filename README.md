# Adab Network Security Tools 🛡️

<p align="center">
  <img src="docs/images/logo.png" alt="Adab Network Security Tools Logo" width="200"/>
  <br>
  <em>A comprehensive network security toolkit for penetration testing and security analysis</em>
</p>

<p align="center">
  <a href="https://github.com/fuondai/Adab_net/actions">
    <img src="https://github.com/fuondai/Adab_net/workflows/CI/CD/badge.svg" alt="Build Status">
  </a>
  <a href="https://github.com/fuondai/Adab_net/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/fuondai/Adab_net" alt="License">
  </a>
  <a href="https://github.com/fuondai/Adab_net/releases">
    <img src="https://img.shields.io/github/v/release/fuondai/Adab_net" alt="Latest Release">
  </a>
</p>

## 📖 Overview

Adab Network Security Tools is a powerful Python-based security toolkit that provides a wide range of network analysis and security assessment capabilities. From basic network reconnaissance to advanced vulnerability scanning, this toolkit is designed for security professionals, network administrators, and penetration testers.

## ✨ Key Features

- 🔍 **Network Reconnaissance**

  - Port scanning with service detection
  - DNS enumeration and analysis
  - WHOIS information gathering
  - Network device discovery
  - Subdomain enumeration

- 🛡️ **Security Analysis**

  - Vulnerability scanning via Shodan integration
  - Authentication testing
  - Service version detection
  - Security configuration analysis
  - SSL/TLS certificate verification

- 📊 **Network Analysis**

  - Packet capture and analysis
  - Network traffic monitoring
  - Protocol analysis
  - Network route tracing
  - ARP scanning

- 🚀 **Enterprise Features**
  - Advanced scanning capabilities
  - Extended API access
  - Priority support
  - Custom scan configurations
  - Detailed reporting

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- pip package manager
- Root/Administrator privileges for certain features

### Installation

1. Clone the repository:

```bash
git clone https://github.com/fuondai/Adab_net.git
cd Adab_net
```

2. Install dependencies:

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install required packages
pip install -r requirements.txt
```

3. Set up configuration:

```bash
# Generate secret key
python server/create_secret_key.py

# Configure environment variables (optional)
export SERVER_HOST=0.0.0.0
export SERVER_PORT=5000
```

### Basic Usage

```bash
# Show help
python main.py -h

# Basic port scan
python main.py -p 80,443 example.com

# DNS enumeration
python main.py --dns example.com

# Vulnerability scan (requires API key)
python main.py --vuln-scan example.com
```

## 📚 Documentation

Detailed documentation is available in the [docs](docs/) directory:

- [Installation Guide](docs/installation.md)
- [User Manual](docs/user-manual.md)
- [API Reference](docs/api-reference.md)
- [Contributing Guidelines](docs/contributing.md)

## 🛠️ Development

### Setting up development environment

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
pylint src/
```

### Docker Support

```bash
# Build image
docker build -t adabnet .

# Run container
docker run -p 5000:5000 adabnet
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/fuondai">
        <img src="https://github.com/fuondai.png" width="100px;" alt="Phuong Dai"/><br />
        <sub><b>Phuong Dai</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/thienan">
        <img src="https://github.com/thienan.png" width="100px;" alt="Thien An"/><br />
        <sub><b>Thien An</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/congdanh">
        <img src="https://github.com/congdanh.png" width="100px;" alt="Cong Danh"/><br />
        <sub><b>Cong Danh</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/huubinh">
        <img src="https://github.com/huubinh.png" width="100px;" alt="Huu Binh"/><br />
        <sub><b>Huu Binh</b></sub>
      </a>
    </td>
  </tr>
</table>

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Shodan](https://www.shodan.io/) for vulnerability scanning capabilities
- [Scapy](https://scapy.net/) for packet manipulation
- All our [contributors](CONTRIBUTORS.md) who have helped improve this project

## 📞 Support

- Create an [Issue](https://github.com/fuondai/Adab_net/issues)
- Email: fuondai1314@gmail.com
- Join our [Discord community](https://discord.gg/adabnet)

## 🔗 Links

- [Project Homepage](https://adabnet.io)
- [Documentation](https://docs.adabnet.io)
- [Bug Tracker](https://github.com/fuondai/Adab_net/issues)
- [Release Notes](CHANGELOG.md)

---

<p align="center">
  Made with ❤️ by the Adab Network Security Team
</p>
