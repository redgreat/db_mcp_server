import time
from typing import Dict, Tuple


class QueryLimiter:
    """简单令牌桶限流器"""
    def __init__(self, rate_per_minute: int = 60):
        self.rate = rate_per_minute
        self.state: Dict[str, Tuple[int, float]] = {}

    def allow(self, key: str) -> bool:
        """校验限流是否允许"""
        now = time.time()
        count, reset_at = self.state.get(key, (0, now + 60))
        if now > reset_at:
            count = 0
            reset_at = now + 60
        if count >= self.rate:
            self.state[key] = (count, reset_at)
            return False
        self.state[key] = (count + 1, reset_at)
        return True

