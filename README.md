# zr_db_mcp_server

中瑞专用数据库MCP服务端 - 企业级数据库访问代理系统

## 项目简介

zr_db_mcp_server 是一个基于Docker部署的安全数据库代理服务，支持MySQL和PostgreSQL。通过访问密钥和多级权限控制，为客户端提供安全的数据库查询服务，所有数据库凭证集中管理，客户端无需知道真实的数据库账号密码。

### 核心特性

- 🔐 **访问控制**：基于访问密钥的三级权限控制（实例/数据库/账号）
- 🛡️ **安全防护**：SQL注入检测、风险评分、IP白名单
- 🔄 **事务支持**：完整的事务管理（开启/提交/回滚/状态查询）
- 📊 **多数据库**：同时支持MySQL和PostgreSQL
- 📡 **实时流式**：支持SSE (Server-Sent Events) 流式查询
- 📝 **审计日志**：完整的访问日志和操作审计
- 🌐 **Web管理**：提供Web管理界面配置实例、数据库、账号和权限
- 🐳 **Docker部署**：使用supervisord管理，非root用户运行

## 快速开始

### 前置要求

- Docker 20.10+
- Docker Compose 1.29+

### 使用Docker Compose部署

1. **克隆项目**

```bash
git clone https://github.com/redgreat/zr_db_mcp_server.git
cd zr_db_mcp_server
```

2. **配置环境变量**

```bash
cp .env.example .env
# 编辑.env文件，修改MASTER_KEY为你自己的密钥
```

3. **启动服务**

```bash
docker-compose up -d
```

4. **检查服务状态**

```bash
docker-compose ps
docker-compose logs -f
```

5. **访问管理界面**

打开浏览器访问: `http://localhost:3000/admin`

### 手动部署

如果不使用Docker，可以手动部署：

```bash
# 安装依赖
pip install -r requirements.txt

# 初始化数据库
python scripts/init_admin_db.py

# 启动服务
uvicorn src.server:app --host 0.0.0.0 --port 3000
```

## 配置说明

### 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `HOST` | 服务监听地址 | `0.0.0.0` |
| `PORT` | 服务端口 | `3000` |
| `MASTER_KEY` | 主密钥（用于加密数据库密码） | `change_this_master_key` |
| `LOG_DIR` | 日志目录 | `logs` |
| `ADMIN_DB_PATH` | 管理数据库路径 | `admin/admin.db` |
| `DB_POOL_MIN_SIZE` | 连接池最小连接数 | `5` |
| `DB_POOL_MAX_SIZE` | 连接池最大连接数 | `20` |

**⚠️ 重要**: 生产环境请务必修改 `MASTER_KEY` 为随机生成的强密钥！

### 目录结构

```
zr_db_mcp_server/
├── config/              # 配置文件目录
│   └── supervisord.conf # Supervisord配置
├── scripts/             # 脚本目录
│   └── init_admin_db.py # 数据库初始化脚本
├── src/                 # 源代码目录
│   ├── admin/          # 管理后台模块
│   ├── db/             # 数据库操作模块
│   ├── security/       # 安全模块
│   ├── tools/          # 工具模块
│   ├── config.py       # 配置加载
│   ├── server.py       # 服务主文件
│   └── logging_utils.py # 日志工具
├── data/               # 数据目录（挂载卷）
├── logs/               # 日志目录（挂载卷）
├── Dockerfile          # Docker镜像构建文件
├── docker-compose.yml  # Docker Compose配置
└── requirements.txt    # Python依赖
```

## 使用指南

### 1. 配置数据库实例

通过管理API或Web界面添加数据库实例：

```bash
curl -X POST http://localhost:3000/admin/instances \
  -H "Content-Type: application/json" \
  -d '{
    "name": "主数据库",
    "host": "192.168.1.100",
    "port": 3306,
    "db_type": "mysql",
    "description": "生产环境MySQL主库"
  }'
```

**支持的数据库类型**: `mysql`, `postgresql`

### 2. 配置数据库

为实例添加数据库：

```bash
curl -X POST http://localhost:3000/admin/databases \
  -d 'instance_id=1&name=myapp_db'
```

### 3. 配置账号

为实例添加数据库账号（密码加密存储）：

```bash
curl -X POST http://localhost:3000/admin/accounts \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id": 1,
    "username": "readonly_user",
    "password": "SecureP@ssw0rd",
    "plugin": ""
  }'
```

### 4. 创建访问密钥

生成客户端访问密钥：

```bash
curl -X POST http://localhost:3000/admin/keys \
  -d 'ak=api_key_001&description=客户端A的访问密钥&enabled=true'
```

### 5. 配置权限

为访问密钥分配权限（指定可以访问的实例/数据库/账号）：

```bash
curl -X POST http://localhost:3000/admin/permissions \
  -d 'key_id=1&instance_id=1&database_id=1&account_id=1&select_only=true'
```

### 6. 执行查询

客户端使用访问密钥查询数据：

```bash
curl -X POST http://localhost:3000/query \
  -H "x-access-key: api_key_001" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_id": 1,
    "database_id": 1,
    "account_id": 1,
    "sql": "SELECT * FROM users LIMIT 10"
  }'
```

## API文档

### 查询接口

#### POST /query
执行SQL查询

**Headers**:
- `x-access-key`: 访问密钥

**Body**:
```json
{
  "instance_id": 1,
  "database_id": 1,
  "account_id": 1,
  "sql": "SELECT * FROM table_name"
}
```

#### GET /sse/query
SSE流式查询

**Headers**:
- `x-access-key`: 访问密钥

**Query Parameters**:
- `instance_id`: 实例ID
- `database_id`: 数据库ID
- `account_id`: 账号ID
- `sql`: SQL语句

### 元数据接口

#### GET /metadata/tables
获取数据库表列表

#### GET /metadata/table_info
获取表结构信息

**Query Parameters**:
- `table`: 表名

### 事务接口

#### POST /transactions/begin
开启事务

#### POST /transactions/commit
提交事务

#### POST /transactions/rollback
回滚事务

#### GET /transactions/status
查询事务状态

### 管理接口

- `GET /admin/keys` - 列出访问密钥
- `POST /admin/keys` - 创建访问密钥
- `GET /admin/instances` - 列出实例
- `POST /admin/instances` - 创建实例
- `GET /admin/databases` - 列出数据库
- `POST /admin/databases` - 创建数据库
- `GET /admin/accounts` - 列出账号
- `POST /admin/accounts` - 创建账号
- `GET /admin/monitor/logs` - 查看日志摘要

## 安全特性

### SQL注入防护

系统内置多层SQL安全检查：

1. **黑名单检测**: 检测危险SQL关键字（DROP, ALTER, DELETE等）
2. **注入模式检测**: 识别常见注入模式（UNION, OR 1=1等）
3. **风险评分**: 对SQL进行风险评分，超过阈值拒绝执行

### 密码加密

所有数据库密码使用Fernet对称加密，基于`MASTER_KEY`派生的固定密钥加密存储。

### 访问控制

三级权限控制：
1. **实例级**: 控制能访问哪些数据库服务器
2. **数据库级**: 控制能访问实例上的哪些数据库
3. **账号级**: 控制使用哪个数据库账号连接

### 审计日志

所有查询操作都会记录到审计日志，包括：
- 访问密钥
- 执行的SQL语句
- 实例/数据库/账号信息
- 返回行数
- 执行时间

## 运维指南

### 查看日志

```bash
# 查看所有日志
docker-compose logs

# 查看服务日志
docker exec db_mcp_server cat /var/log/db_mcp_server/web.out.log

# 查看审计日志
docker exec db_mcp_server cat /var/log/db_mcp_server/audit.log
```

### 备份数据

```bash
# 备份管理数据库
docker cp db_mcp_server:/data/admin/admin.db ./backup/admin.db.backup

# 备份日志
tar -czf logs-backup.tar.gz logs/
```

### 重启服务

```bash
docker-compose restart
```

### 更新服务

```bash
# 拉取最新代码
git pull

# 重新构建并启动
docker-compose up -d --build
```

## 故障排查

### 服务无法启动

1. 检查端口占用: `netstat -nltp | grep 3000`
2. 查看错误日志: `docker-compose logs`
3. 确认环境变量配置正确

### 查询报错"缺少访问密钥"

确认请求Header中包含 `x-access-key` 且密钥已创建并启用

### 查询报错"风险SQL"

SQL被安全检查拦截，检查SQL语句是否包含危险操作

### 连接数据库失败

1. 确认实例配置正确（host、port、db_type）
2. 确认账号密码正确
3. 确认网络连通性
4. 检查数据库是否允许服务器IP连接

## 开发指南

### 本地开发

```bash
# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 初始化数据库
python scripts/init_admin_db.py

# 启动开发服务器
uvicorn src.server:app --reload --host 0.0.0.0 --port 3000
```

### 运行测试

```bash
pytest tests/
```

## 许可证

本项目采用 [MIT License](LICENSE)

## 技术支持

如有问题请提交Issue或联系技术支持团队。
