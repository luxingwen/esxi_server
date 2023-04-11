import hashlib
import hmac
from functools import wraps
from flask import request, jsonify

def validate_signature(secret_key):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            signature_header = request.headers.get('OSP-Signature', '')
            body = request.get_data()
            computed_signature = hmac.new(secret_key.encode('utf-8'), body, hashlib.sha1).hexdigest()

            if not hmac.compare_digest(signature_header, computed_signature):
                return jsonify({'error': 'Invalid signature'}), 401

            return f(*args, **kwargs)
        return decorated_function
    return decorator
