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
        name="list_connections",
        description="列出当前用户有权访问的所有数据库连接。如果不提供 search 参数，则列出全部有权访问的连接。",
        input_schema={
            "type": "object",
            "properties": {
                "search": {
                    "type": "string",
                    "description": "可选搜索关键词，匹配连接名称或数据库类型（如 mysql, postgres 等）"
                }
            }
        }
    ),

    MCPTool(
        name="list_databases",
        description="列出指定连接中的所有数据库",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                }
            },
            "required": ["connection_id"]
        }
    ),

    MCPTool(
        name="list_tables",
        description="列出指定数据库中的所有表",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选，如果不提供则使用连接默认数据库）"
                }
            },
            "required": ["connection_id"]
        }
    ),

    MCPTool(
        name="list_views",
        description="列出指定数据库中的所有视图",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选，如果不提供则使用连接默认数据库）"
                }
            },
            "required": ["connection_id"]
        }
    ),

    MCPTool(
        name="list_procedures",
        description="列出指定数据库中的所有存储过程",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选，如果不提供则使用连接默认数据库）"
                }
            },
            "required": ["connection_id"]
        }
    ),
    
    MCPTool(
        name="describe_table",
        description="查询指定表的结构信息（字段名、类型、键等）",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "table": {
                    "type": "string",
                    "description": "表名"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选）"
                }
            },
            "required": ["connection_id", "table"]
        }
    ),
    
    MCPTool(
        name="execute_query",
        description="执行SELECT查询语句，返回查询结果（只读操作）",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "sql": {
                    "type": "string",
                    "description": "SELECT查询语句"
                }
            },
            "required": ["connection_id", "sql"]
        }
    ),
    
    MCPTool(
        name="execute_sql",
        description="执行任意SQL语句，包括DDL操作（需要DDL权限）",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "sql": {
                    "type": "string",
                    "description": "SQL语句"
                }
            },
            "required": ["connection_id", "sql"]
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
