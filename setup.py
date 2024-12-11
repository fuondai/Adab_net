from setuptools import setup, find_packages

setup(
    name='NetworkScanner',
    version='1.0.0',
    description='A powerful network scanning tool with multiple modules.',
    author='An, Danh, Dai, Binh',
    packages=find_packages(),
    install_requires=[
        'scapy',
        'prettytable',
        'colorama',
        'requests',
        'cryptography',
        'paramiko',
        'python-shodan',
        'python-whois',
        'python-pyshark',
        'mysql-connector-python'
    ],
    entry_points={
        'console_scripts': [
            'network-scanner=main:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
