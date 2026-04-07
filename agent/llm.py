"""LLM abstraction layer - multi-model unified calling via litellm"""

import os
import time
from typing import Any, Dict, List, Optional
import litellm
from dotenv import load_dotenv
from utils.logger import get_logger

logger = get_logger(__name__)
load_dotenv()

PROVIDER_ENV_KEYS = {
    "zhipu": "ZHIPU_API_KEY", "xiaomi": "XIAOMI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY", "volcengine": "VOLCENGINE_API_KEY",
    "dashscope": "DASHSCOPE_API_KEY", "qianfan": "QIANFAN_API_KEY",
    "openai": "OPENAI_API_KEY",
}

PROVIDER_PREFIX = {
    "zhipu": "openai", "xiaomi": "openai", "deepseek": "deepseek",
    "volcengine": "openai", "dashscope": "openai", "qianfan": "openai", "openai": "openai",
}


class LLMClient:
    def __init__(self, config: dict):
        self.models_config = {m["name"]: m for m in config.get("models", [])}
        self.active_model_name = config.get("active_model", "")
        self.retry_count = config.get("retry_count", 3)
        self.retry_delay = config.get("retry_delay", 2)
        self.request_timeout = config.get("request_timeout", 120)
        self.usage_stats: Dict[str, Dict[str, int]] = {}
        litellm.drop_params = True
        litellm.set_verbose = False
        if self.active_model_name:
            logger.info(f"LLM client initialized: [{self.active_model_name}]")

    def _get_model_config(self, model_name: str = None) -> dict:
        name = model_name or self.active_model_name
        if name not in self.models_config:
            raise ValueError(f"Model [{name}] not found. Available: {list(self.models_config.keys())}")
        return self.models_config[name]

    def _get_api_key(self, provider: str) -> str:
        env_key = PROVIDER_ENV_KEYS.get(provider, f"{provider.upper()}_API_KEY")
        return os.getenv(env_key, "")

    def _build_model_string(self, model_config: dict) -> str:
        provider = model_config.get("provider", "openai")
        model_id = model_config.get("model_id", "")
        if provider == "deepseek":
            return f"deepseek/{model_id}"
        return f"openai/{model_id}"

    def chat(self, messages: List[Dict[str, str]], model_name: str = None,
             temperature: float = None, max_tokens: int = None, tools: List[Dict] = None, **kwargs) -> str:
        config = self._get_model_config(model_name)
        provider = config.get("provider", "openai")
        api_key = self._get_api_key(provider)
        api_base = config.get("api_base", "")
        model_string = self._build_model_string(config)
        temp = temperature if temperature is not None else config.get("temperature", 0.1)
        max_tok = max_tokens or config.get("max_tokens", 4096)

        for attempt in range(self.retry_count):
            try:
                call_kwargs = {
                    "model": model_string, "messages": messages, "temperature": temp,
                    "max_tokens": max_tok, "api_key": api_key, "api_base": api_base,
                    "timeout": self.request_timeout,
                }
                if tools:
                    call_kwargs["tools"] = tools
                call_kwargs.update(kwargs)
                response = litellm.completion(**call_kwargs)
                content = response.choices[0].message.content or ""
                usage = response.usage
                if usage:
                    mk = model_name or self.active_model_name
                    if mk not in self.usage_stats:
                        self.usage_stats[mk] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "calls": 0}
                    s = self.usage_stats[mk]
                    s["prompt_tokens"] += getattr(usage, "prompt_tokens", 0)
                    s["completion_tokens"] += getattr(usage, "completion_tokens", 0)
                    s["total_tokens"] += getattr(usage, "total_tokens", 0)
                    s["calls"] += 1
                return content
            except Exception as e:
                error_msg = str(e)
                logger.warning(f"LLM call failed (attempt {attempt + 1}/{self.retry_count}): {error_msg[:200]}")
                if self._should_switch_model(error_msg):
                    new_model = self._switch_to_next_model()
                    if new_model:
                        logger.info(f"Auto-switching model: {self.active_model_name} -> {new_model}")
                        self.active_model_name = new_model
                        config = self._get_model_config()
                        provider = config.get("provider", "openai")
                        api_key = self._get_api_key(provider)
                        api_base = config.get("api_base", "")
                        model_string = self._build_model_string(config)
                        continue
                if attempt < self.retry_count - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
        raise RuntimeError(f"LLM call failed after {self.retry_count} retries")

    def _should_switch_model(self, error_msg: str) -> bool:
        keywords = ["rate_limit", "rate limit", "quota", "insufficient_quota", "billing", "balance", "429", "402", "exceeded"]
        return any(kw in error_msg.lower() for kw in keywords)

    def _switch_to_next_model(self) -> Optional[str]:
        names = list(self.models_config.keys())
        idx = names.index(self.active_model_name) if self.active_model_name in names else -1
        for i in range(1, len(names)):
            next_idx = (idx + i) % len(names)
            next_name = names[next_idx]
            provider = self.models_config[next_name].get("provider", "")
            if self._get_api_key(provider):
                return next_name
        logger.error("No available models!")
        return None

    def switch_model(self, model_name: str) -> None:
        if model_name not in self.models_config:
            raise ValueError(f"Model [{model_name}] not found")
        logger.info(f"Manual model switch: {self.active_model_name} -> {model_name}")
        self.active_model_name = model_name

    def get_usage_stats(self) -> Dict[str, Dict[str, int]]:
        return self.usage_stats

    def list_models(self) -> List[str]:
        return list(self.models_config.keys())
