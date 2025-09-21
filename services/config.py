import os

class Config:
    DEBUG = os.getenv("APP_DEBUG", "1") == "1"
    CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))
    REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "8.0"))

config = Config()
