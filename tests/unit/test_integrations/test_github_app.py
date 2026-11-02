"""Tests for GitHub App authentication (RS256 JWT signing, no network)."""

from __future__ import annotations

import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.integrations.github_app import GitHubAppAuth, _parse_expiry


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return key, pem


class TestConfiguration:
    def test_configured_requires_both_fields(self) -> None:
        assert GitHubAppAuth(app_id="1", private_key="k").configured is True
        assert GitHubAppAuth(app_id="1", private_key="").configured is False
        assert GitHubAppAuth(app_id="", private_key="k").configured is False

    def test_install_url(self) -> None:
        auth = GitHubAppAuth(app_id="1", private_key="k", slug="codeguard")
        assert auth.install_url() == "https://github.com/apps/codeguard/installations/new"

    def test_install_url_empty_without_slug(self) -> None:
        assert GitHubAppAuth(app_id="1", private_key="k").install_url() == ""


class TestJwt:
    def test_signs_rs256_with_iss_claim(self, keypair) -> None:
        key, pem = keypair
        auth = GitHubAppAuth(app_id="123456", private_key=pem)
        token = auth.generate_jwt()

        claims = pyjwt.decode(
            token,
            key.public_key(),
            algorithms=["RS256"],
            options={"verify_exp": False},
        )
        assert claims["iss"] == "123456"
        assert claims["exp"] > time.time()
        # GitHub rejects JWTs valid for more than 10 minutes.
        assert claims["exp"] - claims["iat"] <= 660

    def test_reads_private_key_from_path(self, tmp_path, keypair) -> None:
        key, pem = keypair
        path = tmp_path / "app.pem"
        path.write_text(pem, encoding="utf-8")

        auth = GitHubAppAuth(app_id="9", private_key=str(path))
        claims = pyjwt.decode(
            auth.generate_jwt(),
            key.public_key(),
            algorithms=["RS256"],
            options={"verify_exp": False},
        )
        assert claims["iss"] == "9"

    def test_unescapes_inline_newlines(self, keypair) -> None:
        _, pem = keypair
        auth = GitHubAppAuth(app_id="1", private_key=pem.replace("\n", "\\n"))
        assert "\\n" not in auth._load_private_key()

    def test_raises_without_credentials(self) -> None:
        with pytest.raises(RuntimeError):
            GitHubAppAuth().generate_jwt()


class TestTokenCache:
    def test_cached_token_returned_while_valid(self) -> None:
        auth = GitHubAppAuth(app_id="1", private_key="k")
        auth._token_cache[5] = ("cached-token", time.time() + 3600)
        import asyncio

        assert asyncio.run(auth.get_token(5)) == "cached-token"

    def test_clear_cache(self) -> None:
        auth = GitHubAppAuth(app_id="1", private_key="k")
        auth._token_cache[5] = ("t", time.time() + 3600)
        auth.clear_token_cache()
        assert auth._token_cache == {}


def test_parse_expiry_fallbacks() -> None:
    assert _parse_expiry("") > time.time()
    assert _parse_expiry("not-a-date") > time.time()
    assert _parse_expiry("2030-01-01T00:00:00Z") > time.time()
