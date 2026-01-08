import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from typing import Optional


def _get_fernet(master_key: str) -> Fernet:
    """基于master_key创建固定的Fernet加密器
    
    使用SHA256将master_key转换为32字节密钥，确保相同的master_key
    总是生成相同的Fernet密钥，从而可以正确解密之前加密的数据
    """
    # 使用SHA256将master_key转换为32字节
    key_bytes = hashlib.sha256(master_key.encode('utf-8')).digest()
    # Fernet需要base64编码的32字节密钥
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)


def encrypt_text(plain: str, master_key: str) -> str:
    """加密文本"""
    f = _get_fernet(master_key)
    return f.encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_text(cipher: str, master_key: str) -> str:
    """解密文本"""
    f = _get_fernet(master_key)
    try:
        return f.decrypt(cipher.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""

