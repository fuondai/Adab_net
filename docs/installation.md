# Hướng dẫn Cài đặt

## Yêu cầu Hệ thống

- Python 3.7 trở lên
- pip package manager
- Quyền root/administrator cho một số tính năng
- Npcap (cho Windows) hoặc libpcap (cho Linux)

## Cài đặt trên Windows

1. Cài đặt Python

- Tải Python từ https://www.python.org/downloads/
- Chọn "Add Python to PATH" khi cài đặt

2. Cài đặt Npcap

- Tải Npcap từ https://npcap.com/#download
- Cài đặt với tùy chọn mặc định

3. Cài đặt Project

```bash
# Clone repository
git clone https://github.com/fuondai/Adab_net.git
cd Adab_net

# Chạy script cài đặt
setup.bat
```

## Cài đặt trên Linux

1. Cài đặt các gói phụ thuộc

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv libpcap-dev
```

2. Cài đặt Project

```bash
# Clone repository
git clone https://github.com/fuondai/Adab_net.git
cd Adab_net

# Chạy script cài đặt
chmod +x setup.sh
sudo ./setup.sh
```

## Xác thực Cài đặt

Kiểm tra cài đặt bằng cách chạy:

```bash
python main.py -h
```
