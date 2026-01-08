"""
MCP工具定义
"""
from typing import Dict, Any, List


class MCPTool:
    """MCP工具基类"""
    
    def __init__(self, name: str, description: str, input_schema: Dict[str, Any]):
        self.name = name
        self.description = description
        self.input_schema = input_schema
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为MCP工具定义字典"""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema
        }


# 定义所有可用的MCP工具
MCP_TOOLS = [
    MCPTool(
        name="list_tables",
        description="列出指定数据库的所有表",
        input_schema={
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "integer",
                    "description": "数据库实例ID"
                },
                "database_id": {
                    "type": "integer",
                    "description": "数据库ID"
                },
                "account_id": {
                    "type": "integer",
                    "description": "账号ID"
                }
            },
            "required": ["instance_id", "database_id", "account_id"]
        }
    ),
    
    MCPTool(
        name="describe_table",
        description="查询指定表的结构信息（字段名、类型、键等）",
        input_schema={
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "integer",
                    "description": "数据库实例ID"
                },
                "database_id": {
                    "type": "integer",
                    "description": "数据库ID"
                },
                "account_id": {
                    "type": "integer",
                    "description": "账号ID"
                },
                "table": {
                    "type": "string",
                    "description": "表名"
                }
            },
            "required": ["instance_id", "database_id", "account_id", "table"]
        }
    ),
    
    MCPTool(
        name="execute_query",
        description="执行SELECT查询语句，返回查询结果（只读操作）",
        input_schema={
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "integer",
                    "description": "数据库实例ID"
                },
                "database_id": {
                    "type": "integer",
                    "description": "数据库ID"
                },
                "account_id": {
                    "type": "integer",
                    "description": "账号ID"
                },
                "sql": {
                    "type": "string",
                    "description": "SELECT查询语句"
                }
            },
            "required": ["instance_id", "database_id", "account_id", "sql"]
        }
    ),
    
    MCPTool(
        name="execute_sql",
        description="执行任意SQL语句，包括DDL操作（需要DDL权限）",
        input_schema={
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "integer",
                    "description": "数据库实例ID"
                },
                "database_id": {
                    "type": "integer",
                    "description": "数据库ID"
                },
                "account_id": {
                    "type": "integer",
                    "description": "账号ID"
                },
                "sql": {
                    "type": "string",
                    "description": "SQL语句"
                }
            },
            "required": ["instance_id", "database_id", "account_id", "sql"]
        }
    ),
]


def get_tool_definitions() -> List[Dict[str, Any]]:
    """获取所有MCP工具定义"""
    return [tool.to_dict() for tool in MCP_TOOLS]


def get_tool_by_name(name: str) -> MCPTool:
    """根据名称获取工具"""
    for tool in MCP_TOOLS:
        if tool.name == name:
            return tool
    return None
