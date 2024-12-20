# Hướng dẫn Sử dụng

## Các Tính năng Chính

### 1. Quét Port

```bash
# Quét các port phổ biến
python main.py -p 80,443 example.com

# Quét range port
python main.py -p 1-1000 192.168.1.1

# Quét stealth
python main.py -sS 192.168.1.1 -p 80,443
```

### 2. DNS Enumeration

```bash
# Quét DNS cơ bản
python main.py --dns example.com

# Quét subdomain
python main.py --subdomain example.com
```

### 3. Phân tích Mạng

```bash
# Quét thiết bị trong mạng
python main.py --device-scan 192.168.1.0/24

# Bắt gói tin
python main.py --packet-capture eth0
```

### 4. Quét Lỗ hổng

```bash
# Quét với Shodan
python main.py --vuln-scan example.com

# Quét xác thực
python main.py --auth-scan 192.168.1.1
```

## Tùy chọn Nâng cao

### Định dạng Output

```bash
# Output JSON
python main.py -p 80 example.com --json

# Lưu kết quả
python main.py -p 80 example.com -o results.txt
```

### Tùy chỉnh Quét

```bash
# Số thread
python main.py -p 80 example.com --threads 10

# Timeout
python main.py -p 80 example.com --timeout 5
```
