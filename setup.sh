#!/bin/bash

# Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Cài đặt các package system cần thiết
apt-get update
apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    libpcap-dev \
    tcpdump

# Tạo virtual environment
python3 -m venv venv
source venv/bin/activate

# Cài đặt dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Tạo secret key nếu chưa tồn tại
if [ ! -f "secret.key" ]; then
    python3 server/create_secret_key.py
fi

# Cấp quyền cho các file thực thi
chmod +x main.py
chmod +x server/server.py

echo "Setup completed successfully!"
