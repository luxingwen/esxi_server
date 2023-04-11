# logger.py
import logging
import logging.handlers
from functools import wraps
from flask import request, make_response
from config import config  # 导入 config 模块


log = logging.getLogger('request_logger')
# 配置日志
def setup_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    log_handler = logging.handlers.TimedRotatingFileHandler(config['logging']['log_file'], when='D', interval=1, backupCount=7)
    log_handler.setFormatter(log_formatter)
    log_handler.setLevel(logging.getLevelName(config['logging']['log_level']))

    logger = logging.getLogger('logger')
    logger.addHandler(log_handler)
    logger.setLevel(logging.getLevelName(config['logging']['log_level']))
    return logger

log = setup_logging()

# 记录请求日志的装饰器

def log_request(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 记录请求信息
        request_info = {
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
            "body": request.get_data(as_text=True)
        }
        log.info(f"Request info: {request_info}")

        # 获取响应内容
        response = f(*args, **kwargs)

        # 如果响应是一个 Flask Response 对象，获取其内容
        response_data = response.get_data(as_text=True) if isinstance(response, make_response().__class__) else str(response)

        # 记录响应信息
        response_info = {
            "status_code": response.status_code if isinstance(response, make_response().__class__) else None,
            "headers": dict(response.headers) if isinstance(response, make_response().__class__) else None,
            "body": response_data
        }
        log.info(f"Response info: {response_info}")

        return response

    return decorated_function


