from setuptools import setup, find_packages

setup(
    name="network-scanner",
    version="1.0.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.7",
    install_requires=[
        "flask>=2.0.0",
        "sqlalchemy>=1.4.0",
        "click>=8.0.0",
        "pyjwt>=2.0.0",
        "flasgger>=0.9.5",
        "flask-limiter>=2.0.0",
        "scapy>=2.4.5",
        "cryptography>=3.4.7",
        "requests>=2.26.0",
        "colorama>=0.4.4",
        "paramiko>=2.7.2",
        "python-whois>=0.7.3",
    ],
    extras_require={
        "full": [
            "shodan>=1.25.0",
            "pyshark>=0.4.3",
        ]
    },
    entry_points={
        "console_scripts": [
            "network-scanner=main:main",
            "license-server=server.cli:cli"
        ],
    },
) 