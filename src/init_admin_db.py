import os
import sys
from sqlalchemy import create_engine

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import Config
from src.admin.models import ensure_schema, create_default_admin


def main():
    """初始化管理数据库（PostgreSQL）"""
    # 加载配置
    cfg = Config.load()
    
    print(f"📊 连接管理数据库: {cfg.admin_database.host}:{cfg.admin_database.port}/{cfg.admin_database.database}")
    
    # 创建PostgreSQL引擎
    admin_db_url = cfg.get_admin_db_url()
    engine = create_engine(admin_db_url, pool_pre_ping=True)
    
    try:
        # 创建表结构
        print("📝 创建数据库表...")
        ensure_schema(engine)
        print("✅ 表结构创建完成")
        
        # 创建默认管理员
        print("👤 创建默认管理员账号...")
        create_default_admin(engine, username="admin", password="admin123")
        
        print()
        print("🎉 管理数据库初始化完成!")
        print()
        print("=" * 60)
        print("默认管理员账号:")
        print("  用户名: admin")
        print("  密码: admin123")
        print("⚠️ 请立即登录后修改默认密码!")
        print("=" * 60)
        
    except Exception as e:
        print(f"❌ 初始化失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
