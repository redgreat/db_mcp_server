import re
from typing import Tuple


# 扩展的SQL危险关键字黑名单
DANGEROUS_KEYWORDS = {
    # DDL操作
    "DROP", "CREATE", "ALTER", "TRUNCATE", "RENAME",
    # 权限操作
    "GRANT", "REVOKE",
    # 系统命令
    "EXEC", "EXECUTE", "CALL", "LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE",
    # 数据库操作
    "USE", "SHOW DATABASES", "INFORMATION_SCHEMA",
    # 危险函数
    "SLEEP", "BENCHMARK", "WAITFOR",
    # 注释符号（可能用于注入）
    "--", "/*", "*/", "#"
}

# 高风险SQL模式
HIGH_RISK_PATTERNS = [
    r";\s*DROP",  # 多语句注入
    r"UNION\s+SELECT",  # UNION注入
    r"OR\s+1\s*=\s*1",  # 永真条件
    r"AND\s+1\s*=\s*2",  # 永假条件
    r"'\s*OR\s*'",  # 字符串注入
    r"--\s*$",  # 注释符
    r"/\*.*\*/",  # 块注释
    r"0x[0-9a-fA-F]+",  # 十六进制编码
    r"CONCAT\s*\(",  # 字符串拼接函数（可能用于绕过）
    r"CHAR\s*\(",  # 字符函数
    r"ASCII\s*\(",  # ASCII函数
    r"SUBSTRING\s*\(",  # 子串函数（可能用于盲注）
    r"LOAD_FILE\s*\(",  # 文件读取
    r"INTO\s+OUTFILE",  # 文件写入
    r"INFORMATION_SCHEMA",  # 元数据访问
]


def is_safe_sql(sql: str) -> bool:
    """检查SQL是否安全（增强版）
    
    Args:
        sql: SQL语句
        
    Returns:
        True表示安全，False表示有风险
    """
    sql_upper = sql.upper()
    
    # 检查危险关键字
    for keyword in DANGEROUS_KEYWORDS:
        if keyword in sql_upper:
            return False
    
    # 检查高风险模式
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, sql_upper, re.IGNORECASE):
            return False
    
    return True


def risk_score(sql: str) -> int:
    """计算SQL的风险分值（增强版）
    
    风险分值越高表示越危险
    
    Returns:
        风险分值 (0-100)
    """
    score = 0
    sql_upper = sql.upper()
    
    # 危险关键字检查 (每个+20分)
    for keyword in DANGEROUS_KEYWORDS:
        if keyword in sql_upper:
            score += 20
    
    # 高风险模式检查 (每个+15分)
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, sql_upper, re.IGNORECASE):
            score += 15
    
    # 多语句检查 (有分号+10分)
    if ';' in sql and sql.strip().count(';') > 1:
        score += 10
    
    # 长度检查 (超长SQL可能是攻击)
    if len(sql) > 1000:
        score += 5
    
    # 特殊字符过多
    special_chars = sum(1 for c in sql if c in "'\"\\")
    if special_chars > 10:
        score += 10
    
    return min(score, 100)  # 最高100分


def get_risk_details(sql: str) -> dict:
    """获取SQL风险详情
    
    Returns:
        包含风险详情的字典
    """
    details = {
        "safe": is_safe_sql(sql),
        "risk_score": risk_score(sql),
        "dangerous_keywords": [],
        "risky_patterns": [],
        "warnings": []
    }
    
    sql_upper = sql.upper()
    
    # 检测到的危险关键字
    for keyword in DANGEROUS_KEYWORDS:
        if keyword in sql_upper:
            details["dangerous_keywords"].append(keyword)
    
    # 检测到的风险模式
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, sql_upper, re.IGNORECASE):
            details["risky_patterns"].append(pattern)
    
    # 生成警告信息
    if details["dangerous_keywords"]:
        details["warnings"].append(f"检测到危险关键字: {', '.join(details['dangerous_keywords'][:3])}")
    
    if details["risky_patterns"]:
        details["warnings"].append(f"检测到高风险模式")
    
    if len(sql) > 1000:
        details["warnings"].append("SQL语句过长")
    
    return details
