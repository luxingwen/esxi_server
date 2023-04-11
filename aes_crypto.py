from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes

def encrypt(plain_text, password):
    # 使用密码生成密钥
    key = hashlib.sha256(password.encode("utf-8")).digest()
    # 生成随机初始化向量 (IV)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # 使用 PKCS7 补齐
    padding_length = AES.block_size - (len(plain_text) % AES.block_size)
    plain_text += chr(padding_length) * padding_length
    # 加密
    cipher_text = cipher.encrypt(plain_text.encode("utf-8"))
    # 将 IV 和加密后的密文进行拼接，然后进行 Base64 编码
    return b64encode(iv + cipher_text).decode("utf-8")


def decrypt(cipher_text, password):
    # 使用密码生成密钥
    key = hashlib.sha256(password.encode("utf-8")).digest()
    # 对 Base64 编码的密文进行解码
    cipher_text = b64decode(cipher_text)
    # 提取 IV
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # 解密
    plain_text = cipher.decrypt(cipher_text[AES.block_size:]).decode("utf-8")
    # 移除 PKCS7 补齐
    padding_length = ord(plain_text[-1])
    return plain_text[:-padding_length]
