"""管理后台 API 请求体模型"""
from typing import Optional

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateKeyRequest(BaseModel):
    ak: Optional[str] = None
    description: str = ""
    enabled: bool = True
    sql_risk_check_enabled: bool = True


class TestConnectionRequest(BaseModel):
    host: str
    port: int
    db_type: str
    database: str
    username: str
    password: Optional[str] = None
    connection_id: Optional[int] = None


class ChangePasswordRequest(BaseModel):
    """修改密码请求"""
    old_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    """创建用户请求"""
    username: str
    password: str
    email: Optional[str] = ""
    role: str = "user"  # admin/user


class UpdateUserRequest(BaseModel):
    """更新用户请求"""
    role: Optional[str] = None
    is_active: Optional[bool] = None


class ResetPasswordRequest(BaseModel):
    """重置用户密码请求"""
    new_password: str


class UpdateLLMConfigRequest(BaseModel):
    """更新大模型配置请求"""
    base_url: str
    api_key: Optional[str] = None
    model_name: str
