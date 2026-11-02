"""GitHub App authentication.

A GitHub App is not a personal access token. The flow is:

1. Sign a short-lived RS256 JWT with the app's private key (``iss`` = app id).
2. Exchange that JWT for an *installation* access token, scoped to one org/user.
3. Use the installation token (valid ~1h) as ``Authorization: Bearer ...``.

Only the JWT path needs the private key, and installation tokens are cached in
memory until 60 seconds before expiry.

Configuration (environment):
- ``GITHUB_APP_ID``           numeric app id
- ``GITHUB_APP_PRIVATE_KEY``  PEM content, or a path to the ``.pem`` file
- ``GITHUB_APP_SLUG``         app slug, used to build the install URL
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from src.utils.logging import get_logger

logger = get_logger(__name__)

GITHUB_API = "https://api.github.com"
JWT_TTL_SECONDS = 540  # GitHub caps this at 10 minutes
TOKEN_REFRESH_SKEW = 60


class GitHubAppAuth:
    """Signs app JWTs and caches installation tokens."""

    def __init__(
        self,
        app_id: str | None = None,
        private_key: str | None = None,
        slug: str | None = None,
        api_base: str = GITHUB_API,
    ) -> None:
        self._app_id = (app_id or os.getenv("GITHUB_APP_ID", "")).strip()
        self._private_key = private_key or os.getenv("GITHUB_APP_PRIVATE_KEY", "")
        self._slug = (slug or os.getenv("GITHUB_APP_SLUG", "")).strip()
        self._api_base = api_base.rstrip("/")
        self._token_cache: dict[int, tuple[str, float]] = {}

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    @property
    def configured(self) -> bool:
        """True when both the app id and a private key are present."""
        return bool(self._app_id and self._private_key)

    @property
    def app_id(self) -> str:
        return self._app_id

    @property
    def slug(self) -> str:
        return self._slug

    def install_url(self) -> str:
        """URL the console's "install" button opens."""
        if not self._slug:
            return ""
        return f"https://github.com/apps/{self._slug}/installations/new"

    def _load_private_key(self) -> str:
        raw = self._private_key.strip()
        if not raw:
            raise RuntimeError("GITHUB_APP_PRIVATE_KEY is not configured")
        # Accept either inline PEM or a filesystem path.
        if raw.startswith("-----BEGIN"):
            return raw.replace("\\n", "\n")
        path = Path(raw)
        if path.exists():
            return path.read_text(encoding="utf-8")
        raise RuntimeError("GITHUB_APP_PRIVATE_KEY is neither PEM content nor a valid path")

    # ------------------------------------------------------------------
    # JWT
    # ------------------------------------------------------------------

    def generate_jwt(self, *, ttl: int = JWT_TTL_SECONDS) -> str:
        """Sign an RS256 JWT for app-level API calls."""
        if not self.configured:
            raise RuntimeError("GitHub App is not configured")

        import jwt as pyjwt

        now = int(time.time())
        payload = {
            "iat": now - 60,  # tolerate small clock drift
            "exp": now + ttl,
            "iss": str(self._app_id),
        }
        return pyjwt.encode(payload, self._load_private_key(), algorithm="RS256")

    # ------------------------------------------------------------------
    # Installation tokens
    # ------------------------------------------------------------------

    async def fetch_installation_token(self, installation_id: int) -> dict[str, Any]:
        """Exchange the app JWT for an installation access token."""
        import httpx

        token = self.generate_jwt()
        url = f"{self._api_base}/app/installations/{installation_id}/access_tokens"
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            response.raise_for_status()
            data = response.json()

        expires_at = _parse_expiry(data.get("expires_at", ""))
        self._token_cache[installation_id] = (data["token"], expires_at)
        logger.info(
            "github_installation_token_acquired",
            installation_id=installation_id,
            expires_at=data.get("expires_at", ""),
        )
        return data

    async def get_token(self, installation_id: int) -> str | None:
        """Return a cached or freshly minted installation token."""
        cached = self._token_cache.get(installation_id)
        if cached:
            value, expires_at = cached
            if expires_at - time.time() > TOKEN_REFRESH_SKEW:
                return value

        try:
            data = await self.fetch_installation_token(installation_id)
            return data.get("token")
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "github_installation_token_failed",
                installation_id=installation_id,
                error=str(exc)[:200],
            )
            return None

    async def list_installation_repositories(
        self, installation_id: int
    ) -> list[dict[str, Any]]:
        """List repositories the installation was granted access to."""
        import httpx

        token = await self.get_token(installation_id)
        if not token:
            return []

        url = f"{self._api_base}/installation/repositories"
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                params={"per_page": 100},
            )
            response.raise_for_status()
            return response.json().get("repositories", [])

    def clear_token_cache(self) -> None:
        self._token_cache.clear()


def _parse_expiry(value: str) -> float:
    """Parse GitHub's ISO-8601 ``expires_at`` into a unix timestamp."""
    if not value:
        return time.time() + 3600
    try:
        from datetime import datetime

        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time() + 3600
