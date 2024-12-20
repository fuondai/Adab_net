from setuptools import setup, find_packages

setup(
    name="adabnet",
    version="1.0.0",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "scapy>=2.4.5",
        "cryptography>=3.4.7",
        "requests>=2.26.0", 
        "colorama>=0.4.4",
        "paramiko>=2.7.2",
        "python-whois>=0.7.3",
        "flask>=2.0.0",
        "sqlalchemy>=1.4.0",
        "click>=8.0.0",
        "pyjwt>=2.0.0",
        "flasgger>=0.9.5",
        "flask-limiter>=2.0.0",
        "python-nmap>=0.7.1",
        "dnspython>=2.1.0",
        "beautifulsoup4>=4.9.3",
        "aiohttp>=3.8.1"
    ],
    extras_require={
        "full": [
            "pyshark>=0.4.3",
            "shodan>=1.25.0",
        ],
        "dev": [
            "pytest>=6.2.5",
            "pytest-cov>=2.12.1", 
            "pylint>=2.11.1",
            "black>=21.9b0",
            "mypy>=0.910"
        ]
    },
    entry_points={
        "console_scripts": [
            "adabnet=main:main",
            "adabnet-server=server.cli:cli"
        ],
    },
    author="Phuong Dai",
    author_email="fuondai1314@gmail.com",
    description="A comprehensive network security toolkit",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/fuondai/Adab_net",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
) 