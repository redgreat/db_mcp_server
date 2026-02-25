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

    MCPTool(
        name="export_db_doc",
        description="导出数据库说明文档。生成包含所有表汇总（表名、备注）和每张表字段详情（字段名、类型、长度、可空、默认值、备注）的文档。支持 markdown 和 pdf 两种格式。",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选，默认使用连接的数据库）"
                },
                "format": {
                    "type": "string",
                    "enum": ["markdown", "pdf"],
                    "description": "输出格式，默认 markdown。选择 pdf 时会生成 PDF 文件"
                }
            },
            "required": ["connection_id"]
        }
    ),

    MCPTool(
        name="generate_er_diagram",
        description="生成数据库 ER 图。分析整库表结构和外键关系，自动推断命名约定中的隐含关系（如 user_id → users），输出 Mermaid erDiagram 代码和文字描述。可用于确认实体间关系后再次调整。",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选）"
                },
                "include_columns": {
                    "type": "boolean",
                    "description": "是否包含字段详情，默认 true"
                },
                "include_implicit": {
                    "type": "boolean",
                    "description": "是否包含推断的隐含关系，默认 true"
                },
                "output_type": {
                    "type": "string",
                    "enum": ["mermaid", "text", "both"],
                    "description": "输出类型：mermaid(图表代码)、text(文字描述)、both(两者都输出)，默认 both"
                }
            },
            "required": ["connection_id"]
        }
    ),

    MCPTool(
        name="generate_data_flow",
        description="生成数据库数据流图。分析表结构、外键、触发器、视图、存储过程之间的数据流向关系，输出 Mermaid 流程图代码和文字描述。可以向用户确认各处理流程和数据流向是否正确，逐步完善。",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选）"
                },
                "output_type": {
                    "type": "string",
                    "enum": ["mermaid", "text", "both"],
                    "description": "输出类型，默认 both"
                }
            },
            "required": ["connection_id"]
        }
    ),

    MCPTool(
        name="suggest_columns",
        description="数据库表字段添加建议工具。指定表名和要添加的字段信息，生成 ALTER TABLE DDL，并分析依赖此表的视图、存储过程等关联对象是否需要同步调整。",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "table": {
                    "type": "string",
                    "description": "目标表名"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选）"
                },
                "columns": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "字段名"},
                            "type": {"type": "string", "description": "字段类型，如 VARCHAR(100)、INT、TIMESTAMP 等"},
                            "nullable": {"type": "string", "description": "是否可空，YES 或 NO，默认 YES"},
                            "default": {"type": "string", "description": "默认值"},
                            "comment": {"type": "string", "description": "字段备注"}
                        },
                        "required": ["name", "type"]
                    },
                    "description": "要添加的字段列表"
                },
                "get_table_info": {
                    "type": "boolean",
                    "description": "仅获取表的完整信息（字段、索引、外键、触发器），不生成 DDL。设为 true 时不需要 columns 参数"
                }
            },
            "required": ["connection_id", "table"]
        }
    ),

    MCPTool(
        name="analyze_performance",
        description="数据库性能分析工具。获取当前连接数统计、慢 SQL 列表、锁等待信息、表大小与碎片率、索引使用情况，并给出优化建议（SQL 改写、索引优化、碎片清理等）。",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选）"
                },
                "analysis_type": {
                    "type": "string",
                    "enum": ["full", "connections", "slow_queries", "locks", "table_stats", "index_usage"],
                    "description": "分析类型，默认 full（全面分析）。可选择只分析特定维度"
                }
            },
            "required": ["connection_id"]
        }
    ),

    MCPTool(
        name="compare_schemas",
        description="对比两个数据库连接的 Schema 差异。分析表结构、字段定义、索引的差异，并生成从源库同步到目标库的 DDL 语句。",
        input_schema={
            "type": "object",
            "properties": {
                "source_connection_id": {
                    "type": "integer",
                    "description": "源数据库连接 ID"
                },
                "target_connection_id": {
                    "type": "integer",
                    "description": "目标数据库连接 ID"
                },
                "source_database": {
                    "type": "string",
                    "description": "源数据库名称（可选）"
                },
                "target_database": {
                    "type": "string",
                    "description": "目标数据库名称（可选）"
                },
                "generate_ddl": {
                    "type": "boolean",
                    "description": "是否生成同步 DDL，默认 true"
                }
            },
            "required": ["source_connection_id", "target_connection_id"]
        }
    ),

    MCPTool(
        name="generate_mock_data",
        description="根据表结构和约束自动生成测试数据 INSERT 语句。自动处理自增主键、外键引用（从目标表取真实值）、唯一约束，根据字段名智能生成邮箱/手机号/姓名等数据。",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "table": {
                    "type": "string",
                    "description": "目标表名"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选）"
                },
                "count": {
                    "type": "integer",
                    "description": "生成行数，默认 10，最大 100"
                }
            },
            "required": ["connection_id", "table"]
        }
    ),

    MCPTool(
        name="analyze_sql",
        description="SQL 审查工具。对输入的 SQL 进行执行计划分析（EXPLAIN）、全表扫描检测、索引使用建议、SQL 改写建议（如 SELECT * → 指定字段、NOT IN → NOT EXISTS 等）。",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "sql": {
                    "type": "string",
                    "description": "要分析的 SQL 语句"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选）"
                }
            },
            "required": ["connection_id", "sql"]
        }
    ),

    MCPTool(
        name="backup_table",
        description="表级数据备份工具。通过 CREATE TABLE AS SELECT 方式快速备份指定表的数据到 {表名}_bak_{时间戳} 表。注意：备份不包含索引和约束。需要 DDL 权限。",
        input_schema={
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "integer",
                    "description": "数据库连接 ID"
                },
                "table": {
                    "type": "string",
                    "description": "要备份的表名"
                },
                "database": {
                    "type": "string",
                    "description": "数据库名称（可选）"
                },
                "suffix": {
                    "type": "string",
                    "description": "备份表名后缀（可选，默认使用时间戳 YYYYMMDD_HHMMSS）"
                }
            },
            "required": ["connection_id", "table"]
        }
    ),

    MCPTool(
        name="analyze_db_config",
        description="数据库配置参数分析与调优建议。读取当前数据库配置参数和运行状态，分析 Buffer Pool 命中率、连接数使用率、临时表磁盘比率、慢查询比例等指标，给出参数调整建议。支持 MySQL 和 PostgreSQL。",
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
