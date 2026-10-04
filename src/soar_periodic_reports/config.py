"""Environment-based settings shared by all reports."""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """Raised when a required setting is missing or invalid."""


def env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def require(name: str) -> str:
    value = env(name)
    if value is None:
        raise ConfigError(f"Environment variable {name} is required")
    return value


def env_int(name: str, default: int) -> int:
    raw = env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def env_bool(name: str, default: bool) -> bool:
    raw = env(name)
    return default if raw is None else raw.lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "", separator: str = ",") -> list[str]:
    raw = env(name, default) or ""
    return [item.strip() for item in raw.split(separator) if item.strip()]


def env_pairs(name: str, default: str = "") -> list[tuple[str, str]]:
    """Parse ``a|b;c|d`` into ``[("a", "b"), ("c", "d")]``."""
    pairs = []
    for chunk in env_list(name, default, separator=";"):
        left, sep, right = chunk.partition("|")
        if not sep or not left.strip() or not right.strip():
            raise ConfigError(f"{name}: expected 'name|name' pairs separated by ';', got {chunk!r}")
        pairs.append((left.strip(), right.strip()))
    return pairs


def env_labelled(name: str, default: str = "") -> list[tuple[str, str]]:
    """Parse ``Label=pattern;Other label=pattern`` into ordered pairs."""
    result = []
    for chunk in env_list(name, default, separator=";"):
        label, sep, pattern = chunk.partition("=")
        if not sep or not label.strip() or not pattern.strip():
            raise ConfigError(
                f"{name}: expected 'Label=pattern' entries separated by ';', got {chunk!r}"
            )
        result.append((label.strip(), pattern.strip()))
    return result


@dataclass(frozen=True)
class SoarSettings:
    host: str
    port: int
    org: str
    api_key_id: str
    api_key_secret: str
    cafile: str | None

    @classmethod
    def from_env(cls) -> SoarSettings:
        return cls(
            host=require("SOAR_HOST"),
            port=env_int("SOAR_PORT", 443),
            org=require("SOAR_ORG"),
            api_key_id=require("SOAR_API_KEY_ID"),
            api_key_secret=require("SOAR_API_KEY_SECRET"),
            cafile=env("SOAR_CAFILE"),
        )

    def client_options(self) -> dict[str, object]:
        options: dict[str, object] = {
            "host": self.host,
            "port": self.port,
            "org": self.org,
            "api_key_id": self.api_key_id,
            "api_key_secret": self.api_key_secret,
        }
        if self.cafile:
            options["cafile"] = self.cafile
        return options

    @property
    def ui_base_url(self) -> str:
        port = "" if self.port == 443 else f":{self.port}"
        return f"https://{self.host}{port}"


@dataclass(frozen=True)
class QRadarSettings:
    host: str
    token: str
    api_version: str
    verify: bool | str

    @classmethod
    def from_env(cls) -> QRadarSettings:
        ca_bundle = env("QRADAR_CA_BUNDLE")
        return cls(
            host=require("QRADAR_HOST"),
            token=require("QRADAR_API_TOKEN"),
            api_version=env("QRADAR_API_VERSION", "16.0") or "16.0",
            verify=ca_bundle if ca_bundle else env_bool("QRADAR_VERIFY_SSL", True),
        )


@dataclass(frozen=True)
class MailSettings:
    host: str
    port: int
    auth: str
    use_starttls: bool
    username: str | None
    password: str | None
    oauth_tenant_id: str | None
    oauth_client_id: str | None
    oauth_client_secret: str | None
    oauth_refresh_token: str | None
    sender: str
    recipients: tuple[str, ...]
    cc: tuple[str, ...]

    @classmethod
    def from_env(cls, prefix: str = "") -> MailSettings:
        """Load mail settings; ``prefix`` (e.g. ``WEEKLY_``) allows per-report recipients."""
        recipients = tuple(env_list(f"{prefix}MAIL_TO") or env_list("MAIL_TO"))
        if not recipients:
            raise ConfigError(f"{prefix}MAIL_TO or MAIL_TO must contain at least one address")
        cc = tuple(env_list(f"{prefix}MAIL_CC") or env_list("MAIL_CC"))

        auth = (env("SMTP_AUTH", "none") or "none").lower()
        if auth not in {"none", "login", "oauth2"}:
            raise ConfigError("SMTP_AUTH must be one of: none, login, oauth2")
        settings = cls(
            host=require("SMTP_HOST"),
            port=env_int("SMTP_PORT", 587 if auth != "none" else 25),
            auth=auth,
            use_starttls=env_bool("SMTP_STARTTLS", auth != "none"),
            username=env("SMTP_USERNAME"),
            password=env("SMTP_PASSWORD"),
            oauth_tenant_id=env("SMTP_OAUTH_TENANT_ID"),
            oauth_client_id=env("SMTP_OAUTH_CLIENT_ID"),
            oauth_client_secret=env("SMTP_OAUTH_CLIENT_SECRET"),
            oauth_refresh_token=env("SMTP_OAUTH_REFRESH_TOKEN"),
            sender=require("MAIL_FROM"),
            recipients=recipients,
            cc=cc,
        )
        if auth == "login" and not (settings.username and settings.password):
            raise ConfigError("SMTP_AUTH=login needs SMTP_USERNAME and SMTP_PASSWORD")
        if auth == "oauth2":
            missing = [
                name
                for name, value in (
                    ("SMTP_USERNAME", settings.username),
                    ("SMTP_OAUTH_TENANT_ID", settings.oauth_tenant_id),
                    ("SMTP_OAUTH_CLIENT_ID", settings.oauth_client_id),
                    ("SMTP_OAUTH_CLIENT_SECRET", settings.oauth_client_secret),
                    ("SMTP_OAUTH_REFRESH_TOKEN", settings.oauth_refresh_token),
                )
                if not value
            ]
            if missing:
                raise ConfigError("SMTP_AUTH=oauth2 needs " + ", ".join(missing))
        return settings
