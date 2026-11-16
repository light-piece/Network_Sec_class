"""Backend settings, read from the environment and the repo-root ``.env`` file.

Names match plan section 8 (``.env.example``). Values are validated when the
app starts, so a typo fails fast with a readable message.
"""
from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_network
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from backend.lab_types import LabAddresses

REPO_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    # ---- server ------------------------------------------------------------
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = Field(8000, ge=1, le=65535)

    # ---- AI ----------------------------------------------------------------
    AI_MODE: Literal["mock", "ollama"] = "mock"
    MOCK_AI_SCENARIO: Literal["A", "B"] = "A"
    OLLAMA_URL: str = "http://192.168.64.1:11434"
    OLLAMA_MODEL: str = "qwen3:4b"
    OLLAMA_TIMEOUT: float = Field(120, gt=0)

    # ---- lab topology --------------------------------------------------------
    NS_EMPLOYEE: str = "employee"
    NS_APP: str = "app"
    NS_DB: str = "db"
    NS_ROUTER: str = "router"
    EMPLOYEE_IP: IPv4Address = IPv4Address("10.10.10.10")
    EMPLOYEE_NET: IPv4Network = IPv4Network("10.10.10.0/24")
    APP_IP: IPv4Address = IPv4Address("10.10.20.10")
    APP_SERVICE_PORT: int = Field(8080, ge=1, le=65535)
    DB_IP: IPv4Address = IPv4Address("10.10.30.10")
    DB_PORT: int = Field(5432, ge=1, le=65535)

    # ---- database (used by the company app; listed here so .env validates) ---
    DB_NAME: str = "company"
    DB_USER: str = "app_user"
    DB_PASSWORD: str = "change-me"

    # ---- behaviour -----------------------------------------------------------
    POLL_INTERVAL_SECONDS: float = Field(2, gt=0, le=60)
    MAX_ATTEMPTS: int = Field(3, ge=1, le=10)
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # ---- backend-only additions (not in plan section 8) ---------------------
    LAB_MODE: Literal["real", "fake"] = "real"
    DASHBOARD_DIR: Path = REPO_ROOT / "dashboard"
    LONGPOLL_TIMEOUT_SECONDS: float = Field(15, gt=0, le=120)
    # Display names for the incident's hosts (docs/API_CONTRACT.md "Host").
    EMPLOYEE_HOST_NAME: str = "Employee workstation"
    APP_HOST_NAME: str = "Company app"
    DB_HOST_NAME: str = "Company database"

    @field_validator("LOG_LEVEL", "AI_MODE", "LAB_MODE", mode="before")
    @classmethod
    def _normalise_case(cls, v):
        if not isinstance(v, str):
            return v
        return v.upper() if v.upper() in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else v.lower()

    @field_validator("MOCK_AI_SCENARIO", mode="before")
    @classmethod
    def _upper(cls, v):
        return v.upper() if isinstance(v, str) else v

    @field_validator("OLLAMA_URL")
    @classmethod
    def _url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("OLLAMA_URL must start with http:// or https://")
        return v.rstrip("/")

    @model_validator(mode="after")
    def _topology(self):
        if self.EMPLOYEE_IP not in self.EMPLOYEE_NET:
            raise ValueError(f"EMPLOYEE_IP {self.EMPLOYEE_IP} is not inside EMPLOYEE_NET {self.EMPLOYEE_NET}")
        ips = {self.EMPLOYEE_IP, self.APP_IP, self.DB_IP}
        if len(ips) != 3:
            raise ValueError("EMPLOYEE_IP, APP_IP and DB_IP must be different addresses")
        if self.APP_IP in self.EMPLOYEE_NET or self.DB_IP in self.EMPLOYEE_NET:
            raise ValueError("APP_IP and DB_IP must be outside EMPLOYEE_NET (they sit on their own subnets)")
        if self.APP_SERVICE_PORT == self.DB_PORT:
            raise ValueError("APP_SERVICE_PORT and DB_PORT must differ")
        return self

    # ---- derived -------------------------------------------------------------
    def lab_addresses(self) -> LabAddresses:
        """App and database subnets are the /24 around their addresses (plan section 4)."""
        return LabAddresses(
            employee_ip=str(self.EMPLOYEE_IP),
            employee_net=str(self.EMPLOYEE_NET),
            app_ip=str(self.APP_IP),
            app_net=str(ip_network(f"{self.APP_IP}/24", strict=False)),
            app_port=self.APP_SERVICE_PORT,
            db_ip=str(self.DB_IP),
            db_net=str(ip_network(f"{self.DB_IP}/24", strict=False)),
            db_port=self.DB_PORT,
        )


def load_settings(**overrides) -> Settings:
    """Read settings from the environment and ``.env``; ``overrides`` win (used by tests)."""
    return Settings(**overrides)
