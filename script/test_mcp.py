"""
测试标准 MCP 协议端点
"""
import requests
import json

# 配置
SERVER_URL = "http://localhost:3000"
ACCESS_KEY = "test_key"  # 请替换为实际的访问密钥

def test_mcp_message():
    """测试 MCP 消息端点"""
    print("=" * 60)
    print("测试 MCP 消息端点")
    print("=" * 60)
    
    # 测试 initialize
    print("\n1. 测试 initialize...")
    response = requests.post(
        f"{SERVER_URL}/mcp/message",
        headers={
            "X-Access-Key": ACCESS_KEY,
            "Content-Type": "application/json"
        },
        json={
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {}
        }
    )
    print(f"状态码: {response.status_code}")
    print(f"响应: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    
    # 测试 tools/list
    print("\n2. 测试 tools/list...")
    response = requests.post(
        f"{SERVER_URL}/mcp/message",
        headers={
            "X-Access-Key": ACCESS_KEY,
            "Content-Type": "application/json"
        },
        json={
            "jsonrpc": "2.0",
            "id": "tools-1",
            "method": "tools/list",
            "params": {}
        }
    )
    print(f"状态码: {response.status_code}")
    print(f"响应: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")


if __name__ == "__main__":
    print("\n🚀 DB MCP Server 标准协议测试\n")
    test_mcp_message()
    print("\n测试完成")
