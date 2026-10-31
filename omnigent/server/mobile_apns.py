"""Opt-in APNs alert transport. Construction performs no provider requests."""

from __future__ import annotations

import importlib.util
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import jwt


@dataclass(frozen=True)
class APNsConfiguration:
    team_id: str
    key_id: str
    topic: str
    environment: str
    key_path: Path
    store_path: Path
    server_url: str
    local_development: bool = False

    @classmethod
    def load(cls, env: Mapping[str, str]) -> tuple[APNsConfiguration | None, list[str]]:
        """Validate explicit configuration without opening a key or a network connection."""
        if env.get("OMNIGENT_APNS_ENABLED") != "1":
            return None, ["OMNIGENT_APNS_ENABLED=1"]
        names = (
            "TEAM_ID",
            "KEY_ID",
            "TOPIC",
            "ENVIRONMENT",
            "KEY_PATH",
            "STORE_PATH",
            "SERVER_URL",
        )
        missing = [
            f"OMNIGENT_APNS_{name}" for name in names if not env.get(f"OMNIGENT_APNS_{name}")
        ]
        # The isolated SQLite outbox and live observer require one owning server process.
        if env.get("OMNIGENT_APNS_SINGLE_PROCESS") != "1":
            missing.append("OMNIGENT_APNS_SINGLE_PROCESS=1 (one server worker/replica)")
        if importlib.util.find_spec("h2") is None:
            missing.append("httpx[http2] (h2)")
        if missing:
            return None, missing
        values = {name.lower(): env[f"OMNIGENT_APNS_{name}"] for name in names}
        if values["environment"] not in {"sandbox", "production"}:
            return None, ["OMNIGENT_APNS_ENVIRONMENT=sandbox|production"]
        url = urlsplit(values["server_url"])
        local = env.get("OMNIGENT_APNS_LOCAL_DEVELOPMENT") == "1"
        allowed_scheme = url.scheme == "https" or (
            local and url.scheme == "http" and url.hostname in {"127.0.0.1", "::1"}
        )
        if (
            not allowed_scheme
            or not url.hostname
            or url.username
            or url.password
            or url.path not in {"", "/"}
            or url.query
            or url.fragment
        ):
            return None, ["OMNIGENT_APNS_SERVER_URL (canonical HTTPS origin)"]
        if local and (url.scheme != "http" or url.hostname not in {"127.0.0.1", "::1"}):
            return None, [
                "OMNIGENT_APNS_LOCAL_DEVELOPMENT requires an HTTP loopback server origin"
            ]
        for name in ("key_path", "store_path"):
            if not Path(values[name]).is_absolute():
                return None, [f"OMNIGENT_APNS_{name.upper()} (absolute path)"]
        values["server_url"] = values["server_url"].rstrip("/")
        return cls(
            **{
                **values,
                "key_path": Path(values["key_path"]),
                "store_path": Path(values["store_path"]),
                "local_development": local,
            }
        ), []


@dataclass(frozen=True)
class APNsResult:
    accepted: bool = False
    invalid_token: bool = False
    retryable: bool = False


class APNsTransport:
    def __init__(
        self, config: APNsConfiguration, private_key: str, client: httpx.AsyncClient | None = None
    ) -> None:
        self.config = config
        self._private_key = private_key
        # APNs requires HTTP/2. Neither redirects nor ambient proxy settings are accepted.
        self._client = client or httpx.AsyncClient(
            http2=True, timeout=10, follow_redirects=False, trust_env=False
        )
        self._jwt: str | None = None
        self._issued_at = 0

    async def close(self) -> None:
        await self._client.aclose()

    async def send(
        self, token: str, payload: dict, *, collapse_id: str, expiration: int
    ) -> APNsResult:
        """Send one alert; never log tokens, authorization headers, or provider response bodies."""
        now = int(time.time())
        if self._jwt is None or now - self._issued_at >= 3000:
            self._jwt = jwt.encode(
                {"iss": self.config.team_id, "iat": now},
                self._private_key,
                algorithm="ES256",
                headers={"kid": self.config.key_id},
            )
            self._issued_at = now
        host = (
            "api.sandbox.push.apple.com"
            if self.config.environment == "sandbox"
            else "api.push.apple.com"
        )
        try:
            response = await self._client.post(
                f"https://{host}/3/device/{token}",
                json=payload,
                headers={
                    "authorization": f"bearer {self._jwt}",
                    "apns-topic": self.config.topic,
                    "apns-push-type": "alert",
                    "apns-priority": "10",
                    "apns-collapse-id": collapse_id,
                    "apns-expiration": str(expiration),
                },
            )
        except httpx.TransportError:
            return APNsResult(retryable=True)
        reason = None
        if response.status_code != 200:
            with suppress(ValueError, AttributeError):
                reason = response.json().get("reason")
        if reason == "ExpiredProviderToken":
            self._jwt = None
        return APNsResult(
            accepted=response.status_code == 200,
            invalid_token=response.status_code == 410
            or reason in {"BadDeviceToken", "DeviceTokenNotForTopic"},
            retryable=response.status_code == 429
            or response.status_code >= 500
            or reason == "ExpiredProviderToken",
        )
