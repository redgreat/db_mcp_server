import logging
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from openai import OpenAI
from ..config import Config
from ..security.secret import decrypt_text

logger = logging.getLogger(__name__)


class LLMClient:
    """统一的大模型调用客户端"""

    def __init__(self):
        self.cfg = Config.load()
        self.engine = create_engine(self.cfg.get_admin_db_url(), pool_pre_ping=True)
        self.active_config = self._get_active_config()
        self.client = None

        if self.active_config and self.active_config.get("api_key_enc"):
            api_key = decrypt_text(self.active_config["api_key_enc"], self.cfg.security.master_key)
            self.client = OpenAI(
                api_key=api_key,
                base_url=self.active_config.get("base_url")
            )

    def _get_active_config(self):
        from ..admin.schema_cache import get_admin_tables

        from ..admin.llm_active import ensure_single_llm_active

        ensure_single_llm_active(self.engine)
        llm_configs = get_admin_tables(self.engine)["llm_configs"]
        with Session(self.engine) as session:
            row = session.execute(
                select(llm_configs)
                .where(llm_configs.c.is_active == True)  # noqa: E712
                .order_by(llm_configs.c.id)
                .limit(1)
            ).mappings().first()
            return dict(row) if row else None

    def is_enabled(self) -> bool:
        """检查大模型功能是否已正确配置并启用"""
        return self.client is not None

    def ask(self, system_prompt: str, user_prompt: str) -> dict:
        """
        调用大模型获取智能分析结果

        返回: {
            "content": str,
            "usage": {
                "prompt_tokens": int,
                "completion_tokens": int,
                "total_tokens": int,
                "model": str
            }
        }
        """
        if not self.client:
            raise Exception("大模型功能未启用或 API Key 未配置")

        model_name = self.active_config["model_name"]

        try:
            response = self.client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2
            )

            content = response.choices[0].message.content
            usage = response.usage

            return {
                "content": content,
                "usage": {
                    "prompt_tokens": usage.prompt_tokens if usage else 0,
                    "completion_tokens": usage.completion_tokens if usage else 0,
                    "total_tokens": usage.total_tokens if usage else 0,
                    "model": model_name
                }
            }
        except Exception as e:
            logger.error(f"LLM 调用失败: {str(e)}")
            raise e
