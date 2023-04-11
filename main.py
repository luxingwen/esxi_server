
from flask import Flask, request, jsonify
import hashlib
import hmac
from functools import wraps
from logger import log_request, log
from config import config  # 导入 config 模块
from signature_validation import validate_signature
from remote_executor import remote_execute_command  # 导入 remote_executor 模块
from aes_crypto import encrypt, decrypt  # 导入 aes_crypto 模块

app = Flask(__name__)


@app.route('/execute', methods=['POST'])
@log_request
@validate_signature(config['secret_key'])
def execute():
    if request.method == 'POST':
        data = request.get_json()
        if not data or 'hostname' not in data or 'username' not in data or 'password' not in data or 'command' not in data:
            return jsonify({
                'status': 'error',
                'error': 'Missing required parameters.'
            })
        hostname = data['hostname']
        port = data.get('port', 22)
        username = data['username']
        password = data['password']
        command = data['command']
        timeout = data.get('timeout', 10)
        # 使用解密函数解密密码
        decryption_key = config['aes_key']  # 从 config 模块获取 AES 密钥
        password = decrypt(password, decryption_key)

        result = remote_execute_command(hostname, port, username, password, command, timeout)
        return jsonify(result)

    return jsonify({
        'status': 'error',
        'error': 'Invalid request method.'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)