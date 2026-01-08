import logging
from logging.handlers import RotatingFileHandler
import os
from typing import Optional


def get_logger(name: str, log_dir: str) -> logging.Logger:
    """获取按大小滚动的日志记录器"""
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        file_path = os.path.join(log_dir, f"{name}.log")
        handler = RotatingFileHandler(file_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        logger.addHandler(stream)
    return logger

