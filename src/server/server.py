from flask import Flask, request, jsonify
from functools import wraps
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Invalid token'}), 401
            
        return f(*args, **kwargs)
        
    return decorated

@app.route("/verify", methods=["POST"])
@token_required 
def verify():
    api_key = request.json.get("api_key")
    if api_key in VALID_API_KEYS:
        return jsonify({"status": "valid"}), 200
    return jsonify({"status": "invalid"}), 403 