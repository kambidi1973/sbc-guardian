"""Application configuration using pydantic-settings for environment variable management."""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration for the SBC Guardian application.

    All settings can be overridden via environment variables or a .env file.
    """

    # Application
    app_name: str = "SBC Guardian"
    app_version: str = "1.4.0"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql://sbc:guardian@localhost:5432/sbc_guardian"
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_pool_timeout: int = 30
    db_echo: bool = False

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: Optional[str] = None
    celery_result_backend: Optional[str] = None

    # Security
    secret_key: str = "change-me-in-production"
    encryption_key: Optional[str] = None
    access_token_expire_minutes: int = 60
    algorithm: str = "HS256"

    # SNMP
    snmp_community: str = "public"
    snmp_timeout: int = 10
    snmp_retries: int = 3
    snmp_default_port: int = 161

    # SSH
    ssh_timeout: int = 30
    ssh_key_path: Optional[str] = None

    # Monitoring
    health_check_interval_seconds: int = 60
    metric_retention_days: int = 90
    metric_aggregation_interval_seconds: int = 300

    # Backup
    backup_directory: str = "/app/backups"
    backup_retention_count: int = 30
    backup_encryption_enabled: bool = True

    # CORS
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:8080",
    ]

    @property
    def effective_celery_broker(self) -> str:
        return self.celery_broker_url or self.redis_url

    @property
    def effective_celery_backend(self) -> str:
        return self.celery_result_backend or self.redis_url

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
