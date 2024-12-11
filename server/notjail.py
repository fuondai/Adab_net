from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Cấu hình thư mục gốc mà bạn muốn quét
BASE_DIR = 'test_directory'

# Tạo các thư mục và tệp thử nghiệm trong thư mục gốc
if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)
    os.makedirs(os.path.join(BASE_DIR, 'images'))
    os.makedirs(os.path.join(BASE_DIR, 'uploads'))
    os.makedirs(os.path.join(BASE_DIR, 'admin'))
    with open(os.path.join(BASE_DIR, 'index.html'), 'w') as f:
        f.write('<h1>Welcome to the server!</h1>')
    with open(os.path.join(BASE_DIR, 'uploads', 'file.txt'), 'w') as f:
        f.write('Sample file content.')

@app.route('/')
def index():
    return "Directory Busting Server - Welcome!"

@app.route('/<path:subpath>', methods=['GET'])
def scan(subpath):
    """Quét thư mục và tệp trong BASE_DIR"""
    target_path = os.path.join(BASE_DIR, subpath)

    # Kiểm tra xem thư mục hoặc tệp có tồn tại không
    if os.path.exists(target_path):
        if os.path.isdir(target_path):
            return jsonify({'message': f"Found directory: {subpath}", 'status': 'success'})
        elif os.path.isfile(target_path):
            return jsonify({'message': f"Found file: {subpath}", 'status': 'success'})
    else:
        return jsonify({'message': f"{subpath} not found", 'status': 'error'})


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)
