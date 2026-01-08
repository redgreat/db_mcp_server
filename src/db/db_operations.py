from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import threading
import time


class TransactionInfo:
    """事务信息"""
    def __init__(self, txn_id: str, session: Session):
        self.txn_id = txn_id
        self.session = session
        self.created_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.operations_count = 0
        self.is_active = True


class QueryProxy:
    """数据库查询代理层，支持MySQL和PostgreSQL"""
    
    # 事务默认超时时间（秒）
    DEFAULT_TRANSACTION_TIMEOUT = 300  # 5分钟
    # 清理检查间隔（秒）
    CLEANUP_INTERVAL = 60  # 1分钟
    
    def __init__(self):
        self.engines: Dict[str, Engine] = {}
        self.txn_map: Dict[str, TransactionInfo] = {}
        self._cleanup_thread = None
        self._stop_cleanup = False
        self._lock = threading.Lock()
        
        # 启动自动清理线程
        self._start_cleanup_thread()

    def _engine_key(self, host: str, port: int, user: str, db: str) -> str:
        """生成引擎缓存键"""
        return f"{host}:{port}:{user}:{db}"

    def get_engine(self, host: str, port: int, user: str, pwd: str, db: str, db_type: str = "mysql") -> Engine:
        """获取或创建数据库引擎
        
        Args:
            host: 数据库主机
            port: 数据库端口
            user: 数据库用户名
            pwd: 数据库密码
            db: 数据库名称
            db_type: 数据库类型 ('mysql' 或 'postgresql')
        
        Returns:
            SQLAlchemy引擎实例
        """
        key = self._engine_key(host, port, user, db)
        eng = self.engines.get(key)
        if eng is None:
            if db_type.lower() == "postgresql":
                uri = f"postgresql+psycopg2://{user}:{pwd}@{host}:{port}/{db}"
            else:  # 默认使用MySQL
                uri = f"mysql+pymysql://{user}:{pwd}@{host}:{port}/{db}"
            eng = create_engine(uri, pool_pre_ping=True)
            self.engines[key] = eng
        return eng

    def run_query(self, eng: Engine, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """执行只读查询"""
        with eng.connect() as conn:
            rs = conn.execute(text(sql), params or {})
            rows = [dict(r._mapping) for r in rs]
        return rows

    def begin_transaction(self, eng: Engine, txn_id: str, timeout: Optional[int] = None) -> None:
        """开启事务并缓存会话
        
        Args:
            eng: 数据库引擎
            txn_id: 事务ID
            timeout: 超时时间（秒），None使用默认值
        """
        with self._lock:
            if txn_id in self.txn_map:
                raise ValueError(f"事务 {txn_id} 已存在")
            
            sess = Session(eng)
            sess.begin()
            
            txn_info = TransactionInfo(txn_id, sess)
            if timeout is not None:
                txn_info.timeout = timeout
            else:
                txn_info.timeout = self.DEFAULT_TRANSACTION_TIMEOUT
            
            self.txn_map[txn_id] = txn_info

    def execute_in_transaction(self, txn_id: str, sql: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """在事务中执行SQL
        
        Args:
            txn_id: 事务ID
            sql: SQL语句
            params: 参数
            
        Returns:
            执行结果
        """
        with self._lock:
            txn_info = self.txn_map.get(txn_id)
            if not txn_info:
                raise ValueError(f"事务 {txn_id} 不存在")
            
            if not txn_info.is_active:
                raise ValueError(f"事务 {txn_id} 已失效")
            
            # 更新活动时间
            txn_info.last_activity = datetime.utcnow()
            txn_info.operations_count += 1
            
            result = txn_info.session.execute(text(sql), params or {})
            return result

    def commit(self, txn_id: str) -> None:
        """提交事务"""
        with self._lock:
            txn_info = self.txn_map.get(txn_id)
            if txn_info:
                try:
                    txn_info.session.commit()
                finally:
                    txn_info.session.close()
                    txn_info.is_active = False
                    del self.txn_map[txn_id]

    def rollback(self, txn_id: str) -> None:
        """回滚事务"""
        with self._lock:
            txn_info = self.txn_map.get(txn_id)
            if txn_info:
                try:
                    txn_info.session.rollback()
                finally:
                    txn_info.session.close()
                    txn_info.is_active = False
                    del self.txn_map[txn_id]

    def txn_status(self, txn_id: str) -> Dict[str, Any]:
        """查询事务状态（增强版）"""
        with self._lock:
            txn_info = self.txn_map.get(txn_id)
            if not txn_info:
                return {
                    "active": False,
                    "exists": False
                }
            
            now = datetime.utcnow()
            age_seconds = (now - txn_info.created_at).total_seconds()
            idle_seconds = (now - txn_info.last_activity).total_seconds()
            remaining_seconds = max(0, txn_info.timeout - age_seconds)
            
            return {
                "active": txn_info.is_active,
                "exists": True,
                "created_at": txn_info.created_at.isoformat(),
                "last_activity": txn_info.last_activity.isoformat(),
                "age_seconds": age_seconds,
                "idle_seconds": idle_seconds,
                "timeout_seconds": txn_info.timeout,
                "remaining_seconds": remaining_seconds,
                "operations_count": txn_info.operations_count,
                "will_timeout": remaining_seconds <= 0
            }
    
    def list_transactions(self) -> List[Dict[str, Any]]:
        """列出所有活跃事务"""
        with self._lock:
            transactions = []
            for txn_id, txn_info in self.txn_map.items():
                now = datetime.utcnow()
                age_seconds = (now - txn_info.created_at).total_seconds()
                idle_seconds = (now - txn_info.last_activity).total_seconds()
                
                transactions.append({
                    "txn_id": txn_id,
                    "active": txn_info.is_active,
                    "age_seconds": age_seconds,
                    "idle_seconds": idle_seconds,
                    "operations_count": txn_info.operations_count
                })
            return transactions
    
    def _start_cleanup_thread(self):
        """启动自动清理线程"""
        def cleanup_worker():
            while not self._stop_cleanup:
                try:
                    self._cleanup_expired_transactions()
                except Exception as e:
                    print(f"事务清理错误: {e}")
                time.sleep(self.CLEANUP_INTERVAL)
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
    
    def _cleanup_expired_transactions(self):
        """清理超时的事务"""
        now = datetime.utcnow()
        expired_txns = []
        
        with self._lock:
            for txn_id, txn_info in list(self.txn_map.items()):
                age = (now - txn_info.created_at).total_seconds()
                if age > txn_info.timeout:
                    expired_txns.append(txn_id)
        
        # 回滚超时的事务
        for txn_id in expired_txns:
            try:
                print(f"⚠️ 自动回滚超时事务: {txn_id}")
                self.rollback(txn_id)
            except Exception as e:
                print(f"清理事务 {txn_id} 失败: {e}")
    
    def shutdown(self):
        """关闭代理，清理资源"""
        self._stop_cleanup = True
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
        
        # 清理所有活跃事务
        with self._lock:
            for txn_id in list(self.txn_map.keys()):
                try:
                    self.rollback(txn_id)
                except:
                    pass


