from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import jwt

def setup_security(app):
    # Rate limiting
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )
    
    # JWT Authentication
    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'message': 'Missing token'}), 401
            try:
                jwt.decode(token, app.config['SECRET_KEY'])
                return f(*args, **kwargs)
            except:
                return jsonify({'message': 'Invalid token'}), 401
        return decorated
    
    return limiter, require_auth 