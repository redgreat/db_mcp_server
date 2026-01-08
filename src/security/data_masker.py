"""
数据脱敏模块
"""
import re
from typing import Any, List, Dict, Optional


class DataMasker:
    """数据脱敏器"""
    
    # 敏感字段名模式（不区分大小写）
    SENSITIVE_FIELD_PATTERNS = [
        r'password',
        r'passwd',
        r'pwd',
        r'secret',
        r'token',
        r'api_key',
        r'access_key',
        r'private_key',
        r'credit_card',
        r'card_number',
        r'cvv',
        r'ssn',
        r'id_card',
        r'phone',
        r'mobile',
        r'email',
        r'address'
    ]
    
    def __init__(self, enabled: bool = True, mask_char: str = '*'):
        """
        Args:
            enabled: 是否启用脱敏
            mask_char: 脱敏字符
        """
        self.enabled = enabled
        self.mask_char = mask_char
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.SENSITIVE_FIELD_PATTERNS
        ]
    
    def is_sensitive_field(self, field_name: str) -> bool:
        """判断字段是否为敏感字段"""
        if not field_name:
            return False
        
        for pattern in self._compiled_patterns:
            if pattern.search(field_name):
                return True
        return False
    
    def mask_value(self, value: Any, mask_length: int = 4) -> str:
        """脱敏单个值
        
        Args:
            value: 要脱敏的值
            mask_length: 保留明文的字符数
            
        Returns:
            脱敏后的字符串
        """
        if value is None:
            return None
        
        str_value = str(value)
        if len(str_value) <= mask_length:
            return self.mask_char * len(str_value)
        
        # 保留前面的字符，后面全部脱敏
        return str_value[:mask_length] + self.mask_char * (len(str_value) - mask_length)
    
    def mask_email(self, email: str) -> str:
        """脱敏邮箱地址"""
        if not email or '@' not in email:
            return email
        
        local, domain = email.split('@', 1)
        if len(local) <= 2:
            masked_local = self.mask_char * len(local)
        else:
            masked_local = local[0] + self.mask_char * (len(local) - 2) + local[-1]
        
        return f"{masked_local}@{domain}"
    
    def mask_phone(self, phone: str) -> str:
        """脱敏手机号"""
        if not phone:
            return phone
        
        phone_digits = re.sub(r'\D', '', phone)
        if len(phone_digits) < 7:
            return self.mask_char * len(phone)
        
        # 显示前3位和后4位
        return phone[:3] + self.mask_char * (len(phone) - 7) + phone[-4:]
    
    def mask_card_number(self, card_number: str) -> str:
        """脱敏卡号"""
        if not card_number:
            return card_number
        
        card_digits = re.sub(r'\D', '', card_number)
        if len(card_digits) < 8:
            return self.mask_char * len(card_number)
        
        # 只显示后4位
        masked_part = self.mask_char * (len(card_number) - 4)
        return masked_part + card_number[-4:]
    
    def mask_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """脱敏单行数据
        
        Args:
            row: 原始数据行（字典）
            
        Returns:
            脱敏后的数据行
        """
        if not self.enabled or not row:
            return row
        
        masked_row = {}
        for field_name, value in row.items():
            if self.is_sensitive_field(field_name):
                # 根据字段类型选择脱敏方法
                field_lower = field_name.lower()
                if 'email' in field_lower:
                    masked_row[field_name] = self.mask_email(str(value)) if value else value
                elif 'phone' in field_lower or 'mobile' in field_lower:
                    masked_row[field_name] = self.mask_phone(str(value)) if value else value
                elif 'card' in field_lower or 'cvv' in field_lower:
                    masked_row[field_name] = self.mask_card_number(str(value)) if value else value
                else:
                    masked_row[field_name] = self.mask_value(value)
            else:
                masked_row[field_name] = value
        
        return masked_row
    
    def mask_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """脱敏查询结果集
        
        Args:
            results: 原始查询结果列表
            
        Returns:
            脱敏后的结果列表
        """
        if not self.enabled or not results:
            return results
        
        return [self.mask_row(row) for row in results]
