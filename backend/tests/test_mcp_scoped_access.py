"""Guards for datasource-scoped MCP credentials exported from API keys."""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

# sqlbot_xpack creates runtime directories at import time. Point them at a
# temporary tree before any application module loads settings.
_TEST_ROOT = tempfile.mkdtemp(prefix="sqlbot-mcp-test-")
for _name, _sub in {
    "BASE_DIR": "",
    "LOG_DIR": "logs",
    "MCP_IMAGE_PATH": "images",
    "SCRIPT_DIR": "scripts",
    "UPLOAD_DIR": "files",
    "EXCEL_PATH": "excel",
    "LOCAL_MODEL_PATH": "models",
}.items():
    os.environ.setdefault(_name, os.path.join(_TEST_ROOT, _sub) if _sub else _TEST_ROOT)
os.environ.setdefault("CACHE_TYPE", "None")

import jwt
from fastapi import HTTPException

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

# Import xpack before application modules, mirroring main.py. Otherwise the
# audit decorator and xpack's config API import each other in a cycle.
import sqlbot_xpack  # noqa: E402,F401

from apps.mcp import auth as mcp_auth  # noqa: E402
from apps.system.api.apikey import mcp_config  # noqa: E402
from apps.system.middleware.auth import TokenMiddleware  # noqa: E402
from apps.system.models.system_model import ApiKeyModel  # noqa: E402
from apps.datasource.models.datasource import CoreDatasource  # noqa: E402
from common.core import security  # noqa: E402

SECRET = "mcp-api-key-secret-0123456789abcdef"


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def first(self):
        return self._value


class _FakeSession:
    def __init__(self, *, workspace=None, datasource=None, api_key=None):
        self.workspace = workspace
        self.datasource = datasource
        self.api_key = api_key

    def exec(self, _statement):
        return _FakeResult(self.workspace)

    def get(self, model, _pk):
        if model is ApiKeyModel:
            return self.api_key
        if model is CoreDatasource:
            return self.datasource
        return None


class _FakeRequest:
    def __init__(self, headers=None, *, scheme="http", hostname="sqlbot.local"):
        self.headers = headers or {}
        self.url = SimpleNamespace(scheme=scheme, hostname=hostname)


def _api_key(**overrides):
    values = {
        "access_key": "ak-test",
        "secret_key": SECRET,
        "uid": 7,
        "status": True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _scoped_token(*, secret=SECRET, access_key="ak-test", uid=7, oid=3, datasource_id=5, scope="mcp"):
    return jwt.encode(
        {
            "access_key": access_key,
            "scope": scope,
            "uid": uid,
            "oid": oid,
            "datasource_id": datasource_id,
            "iat": 1,
        },
        secret,
        algorithm=security.ALGORITHM,
    )


class ScopedPrincipalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.user = SimpleNamespace(
            id=7, account="user", oid=3, status=1, weight=1, isAdmin=False
        )
        self.workspace = SimpleNamespace(weight=1)
        self.datasource = SimpleNamespace(id=5, oid=3, name="sales")

    def _session(self):
        return _FakeSession(
            workspace=self.workspace,
            datasource=self.datasource,
            api_key=_api_key(),
        )

    async def test_accepts_matching_scope(self):
        request = _FakeRequest({"authorization": f"Bearer {_scoped_token()}"})
        with (
            patch.object(mcp_auth, "get_api_key_uncached", AsyncMock(return_value=_api_key())),
            patch.object(mcp_auth, "get_user_info_uncached", AsyncMock(return_value=self.user)),
        ):
            principal = await mcp_auth.resolve_mcp_principal(self._session(), request)

        self.assertEqual(principal.scope.uid, 7)
        self.assertEqual(principal.scope.oid, 3)
        self.assertEqual(principal.scope.datasource_id, 5)
        self.assertEqual(principal.user.oid, 3)

    async def test_rejects_wrong_signature(self):
        request = _FakeRequest(
            {"authorization": f"Bearer {_scoped_token(secret='another-secret')}"}
        )
        with (
            patch.object(mcp_auth, "get_api_key_uncached", AsyncMock(return_value=_api_key())),
            patch.object(mcp_auth, "get_user_info_uncached", AsyncMock(return_value=self.user)),
        ):
            with self.assertRaises(HTTPException) as raised:
                await mcp_auth.resolve_mcp_principal(self._session(), request)
        self.assertEqual(raised.exception.status_code, 403)

    async def test_rejects_disabled_key(self):
        request = _FakeRequest({"authorization": f"Bearer {_scoped_token()}"})
        with patch.object(
            mcp_auth, "get_api_key_uncached", AsyncMock(return_value=_api_key(status=False))
        ):
            with self.assertRaises(HTTPException) as raised:
                await mcp_auth.resolve_mcp_principal(self._session(), request)
        self.assertEqual(raised.exception.status_code, 403)

    async def test_rejects_datasource_outside_scope(self):
        request = _FakeRequest({"authorization": f"Bearer {_scoped_token()}"})
        self.datasource.oid = 99
        with (
            patch.object(mcp_auth, "get_api_key_uncached", AsyncMock(return_value=_api_key())),
            patch.object(mcp_auth, "get_user_info_uncached", AsyncMock(return_value=self.user)),
        ):
            with self.assertRaises(HTTPException) as raised:
                await mcp_auth.resolve_mcp_principal(self._session(), request)
        self.assertEqual(raised.exception.status_code, 403)

    async def test_rejects_plain_user_token_in_authorization(self):
        user_token = jwt.encode({"id": 7}, "user-secret", algorithm=security.ALGORITHM)
        request = _FakeRequest({"authorization": f"Bearer {user_token}"})
        with self.assertRaises(HTTPException) as raised:
            await mcp_auth.resolve_mcp_principal(self._session(), request)
        self.assertEqual(raised.exception.status_code, 403)

    async def test_legacy_body_token_has_no_scope(self):
        request = _FakeRequest()
        with patch.object(mcp_auth, "get_user", return_value=self.user):
            principal = await mcp_auth.resolve_mcp_principal(
                self._session(), request, token="legacy"
            )
        self.assertIsNone(principal.scope)

    async def test_missing_credentials_are_rejected(self):
        with self.assertRaises(HTTPException) as raised:
            await mcp_auth.resolve_mcp_principal(self._session(), _FakeRequest())
        self.assertEqual(raised.exception.status_code, 403)


class ScopedTokenNotApiKeyTests(unittest.IsolatedAsyncioTestCase):
    async def test_ask_token_rejects_scoped_jwt(self):
        middleware = TokenMiddleware(app=None)
        ok, message = await middleware.validateAskToken(
            "sk " + _scoped_token(), trans=None
        )
        self.assertFalse(ok)
        self.assertIn("Scoped MCP", str(message))


class ExportConfigTests(unittest.IsolatedAsyncioTestCase):
    def _session(self, *, uid=7, ds_oid=3, status=True):
        return _FakeSession(
            api_key=_api_key(uid=uid, status=status),
            datasource=SimpleNamespace(id=5, oid=ds_oid, name="Sales DB"),
        )

    async def test_exports_scoped_config(self):
        response = await mcp_config(
            self._session(),
            SimpleNamespace(id=7, oid=3),
            _FakeRequest(),
            id=1,
            datasource_id=5,
        )
        self.assertEqual(response.headers["cache-control"], "no-store")
        result = json.loads(response.body)
        self.assertEqual(result["url"], "http://sqlbot.local:8001/mcp")
        self.assertEqual(result["datasource"], {"id": 5, "name": "Sales DB"})
        server = result["config"]["mcpServers"]["sqlbot-Sales-DB-5"]
        token = server["headers"]["Authorization"].removeprefix("Bearer ")
        payload = jwt.decode(token, SECRET, algorithms=[security.ALGORITHM])
        self.assertEqual(payload["scope"], "mcp")
        self.assertEqual(payload["oid"], 3)
        self.assertEqual(payload["datasource_id"], 5)
        self.assertEqual(payload["uid"], 7)

    async def test_rejects_other_users_key(self):
        with self.assertRaises(PermissionError):
            await mcp_config(
                self._session(uid=99),
                SimpleNamespace(id=7, oid=3),
                _FakeRequest(),
                id=1,
                datasource_id=5,
            )

    async def test_rejects_disabled_key(self):
        with self.assertRaises(ValueError):
            await mcp_config(
                self._session(status=False),
                SimpleNamespace(id=7, oid=3),
                _FakeRequest(),
                id=1,
                datasource_id=5,
            )

    async def test_rejects_datasource_from_another_workspace(self):
        with self.assertRaises(PermissionError):
            await mcp_config(
                self._session(ds_oid=99),
                SimpleNamespace(id=7, oid=3),
                _FakeRequest(),
                id=1,
                datasource_id=5,
            )


if __name__ == "__main__":
    unittest.main()
