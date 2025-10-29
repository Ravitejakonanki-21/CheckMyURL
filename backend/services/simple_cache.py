import time
from typing import Any, Optional

try:
    # Optional config integration
    from services.config import config  # provides CACHE_TTL
    DEFAULT_TTL = int(getattr(config, "CACHE_TTL", 300))
except Exception:
    DEFAULT_TTL = 300


class SimpleCache:
    def __init__(self, ttl: int = DEFAULT_TTL):
        self.ttl = ttl
        self.store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        item = self.store.get(key)
        if not item:
            return None
        ts, value = item
        if time.time() - ts > self.ttl:
            self.store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any):
        self.store[key] = (time.time(), value)


# Use config-driven TTL by default, but allow override in tests
cache = SimpleCache(ttl=DEFAULT_TTL)
