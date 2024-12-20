import logging
import os
from datetime import datetime

def setup_logging():
    """Thiết lập logging cho ứng dụng"""
    
    # Tạo thư mục logs nếu chưa tồn tại
    if not os.path.exists('logs'):
        os.makedirs('logs')
        
    # Định dạng tên file log theo ngày
    log_file = f"logs/scanner_{datetime.now().strftime('%Y%m%d')}.log"
    
    # Cấu hình logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    ) 