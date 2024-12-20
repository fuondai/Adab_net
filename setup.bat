@echo off
REM Kiểm tra Python đã được cài đặt chưa
python --version >nul 2>&1
if errorlevel 1 (
    echo Python chưa được cài đặt. Vui lòng cài đặt Python trước.
    exit /b 1
)

REM Cài đặt các công cụ cần thiết
echo Installing required tools...
winget install -e --id Wireshark.Wireshark
winget install -e --id Nmap.Nmap

REM Tạo và kích hoạt virtual environment
python -m venv venv
call venv\Scripts\activate.bat

REM Nâng cấp pip và cài đặt các dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

REM Tạo secret key nếu chưa tồn tại
if not exist "secret.key" (
    python src\server\create_secret_key.py
)

echo Setup completed successfully! 