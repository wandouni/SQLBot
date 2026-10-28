"""Tests for the LangBot application-center single sign-on endpoints."""

import asyncio
import hashlib
import hmac
import json
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import jwt

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from apps.system.api import langbot_sso  # noqa: E402
from apps.system.models.system_model import UserWsModel  # noqa: E402
from apps.system.models.user import UserModel  # noqa: E402
from common.core.config import settings  # noqa: E402
from common.core.schemas import TokenPayload  # noqa: E402
from common.utils.whitelist import whiteUtils  # noqa: E402

SECRET = "langbot-sqlbot-shared-secret-0123456789"
TICKET_PATH = "/sqlbot/api/v1/system/langbot/sso/ticket"


def _sign(secret: str, *, timestamp: str, nonce: str, path: str, body: bytes) -> str:
    signing = "\n".join(
        [
            "v1",
            timestamp,
            nonce,
            "POST",
            path,
            hashlib.sha256(body).hexdigest(),
        ]
    )
    return hmac.new(secret.encode(), signing.encode(), hashlib.sha256).hexdigest()


class _FakeRequest:
    def __init__(
        self,
        body: bytes = b"{}",
        *,
        path: str = TICKET_PATH,
        headers: dict | None = None,
        cookies: dict | None = None,
    ) -> None:
        self._body = body
        self.method = "POST"
        self.scope = {"path": path}
        self.url = SimpleNamespace(path=path)
        self.headers = headers or {}
        self.cookies = cookies or {}

    async def body(self) -> bytes:
        return self._body

    async def json(self):
        return json.loads(self._body)


class _Result:
    def __init__(self, value) -> None:
        self._value = value

    def first(self):
        return self._value

    def all(self):
        return [] if self._value is None else [self._value]


class _FakeSession:
    def __init__(self, db_user=None, membership=None) -> None:
        self.db_user = db_user
        self.membership = membership
        self.added: list = []
        self.flushed = 0
        self.rolled_back = False

    def exec(self, statement):
        return _Result(self.membership)

    def add(self, obj) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        self.flushed += 1

    def rollback(self) -> None:
        self.rolled_back = True

    def get(self, model, pk):
        if self.db_user is not None and self.db_user.id == pk:
            return self.db_user
        return None


class _SettingsPatch:
    """Enable the handoff with a known secret for the duration of one test."""

    def __enter__(self):
        self._patches = [
            patch.object(settings, "LANGBOT_SSO_ENABLED", True),
            patch.object(settings, "LANGBOT_SSO_SHARED_SECRET", SECRET),
            patch.object(settings, "LANGBOT_SSO_TICKET_TTL_SECONDS", 60),
            patch.object(settings, "LANGBOT_SSO_CLOCK_SKEW_SECONDS", 60),
            patch.object(settings, "LANGBOT_SSO_NONCE_TTL_SECONDS", 120),
            patch.object(settings, "CONTEXT_PATH", "/sqlbot"),
        ]
        for patcher in self._patches:
            patcher.start()
        langbot_sso._ticket_store.clear()
        langbot_sso._nonce_store.clear()

    def __exit__(self, *args) -> None:
        for patcher in reversed(self._patches):
            patcher.stop()
        langbot_sso._ticket_store.clear()
        langbot_sso._nonce_store.clear()


def _signed_request(payload: dict, *, nonce: str | None = None, timestamp: int | None = None, secret: str = SECRET) -> _FakeRequest:
    body = json.dumps(payload, separators=(",", ":")).encode()
    timestamp_raw = str(timestamp if timestamp is not None else int(time.time()))
    nonce = nonce or "0123456789abcdef0123456789abcdef"
    return _FakeRequest(
        body,
        headers={
            "X-LangBot-SSO-Version": "v1",
            "X-LangBot-SSO-Timestamp": timestamp_raw,
            "X-LangBot-SSO-Nonce": nonce,
            "X-LangBot-SSO-Signature": _sign(
                secret, timestamp=timestamp_raw, nonce=nonce, path=TICKET_PATH, body=body
            ),
        },
    )


def _payload(binding_hash: str | None = None) -> dict:
    return {
        "account": "zhangsan",
        "account_uuid": "langbot-uuid",
        "binding_hash": binding_hash or hashlib.sha256(b"browser-binding").hexdigest(),
    }


def _user(**overrides):
    values = {
        "id": 42,
        "account": "zhangsan",
        "name": "zhangsan",
        "email": "zhangsan@example.com",
        "oid": 1,
        "status": 1,
        "origin": 0,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class WhitelistTest(unittest.TestCase):
    def test_sso_paths_bypass_token_middleware(self) -> None:
        with patch.object(settings, "CONTEXT_PATH", "/sqlbot"):
            self.assertTrue(whiteUtils.is_whitelisted("/sqlbot/api/v1/system/langbot/sso/exchange"))
            self.assertTrue(whiteUtils.is_whitelisted("/sqlbot/api/v1/system/langbot/sso/ticket"))


class SignatureTest(unittest.IsolatedAsyncioTestCase):
    def test_valid_signature_is_accepted_once(self) -> None:
        with _SettingsPatch():
            request = _signed_request(_payload())
            verified, body = asyncio.run(langbot_sso._verify_signed_request(request))
            self.assertTrue(verified)
            self.assertEqual(json.loads(body)["account"], "zhangsan")

            replay = _signed_request(_payload())
            replay.headers = {
                **request.headers,
            }
            replayed, _ = asyncio.run(langbot_sso._verify_signed_request(replay))
            self.assertFalse(replayed)

    def test_wrong_secret_is_rejected(self) -> None:
        with _SettingsPatch():
            request = _signed_request(_payload(), secret="another-secret-value-0123456789")
            verified, _ = asyncio.run(langbot_sso._verify_signed_request(request))
            self.assertFalse(verified)

    def test_stale_timestamp_is_rejected(self) -> None:
        with _SettingsPatch():
            request = _signed_request(_payload(), timestamp=int(time.time()) - 120)
            verified, _ = asyncio.run(langbot_sso._verify_signed_request(request))
            self.assertFalse(verified)

    def test_tampered_body_is_rejected(self) -> None:
        with _SettingsPatch():
            request = _signed_request(_payload())
            request._body = request._body.replace(b"zhangsan", b"admin")
            verified, _ = asyncio.run(langbot_sso._verify_signed_request(request))
            self.assertFalse(verified)

    def test_oversized_body_is_rejected(self) -> None:
        with _SettingsPatch():
            request = _signed_request(_payload())
            request._body = b"x" * (langbot_sso._MAX_BODY_BYTES + 1)
            verified, _ = asyncio.run(langbot_sso._verify_signed_request(request))
            self.assertFalse(verified)

    def test_disabled_service_refuses_ticket(self) -> None:
        with patch.object(settings, "LANGBOT_SSO_ENABLED", False):
            response = asyncio.run(langbot_sso.issue_ticket(_signed_request(_payload()), _FakeSession()))
        self.assertEqual(503, response.status_code)


class AccountTest(unittest.TestCase):
    def test_normalize_account(self) -> None:
        self.assertEqual("zhangsan", langbot_sso._normalize_account(" zhangsan "))
        self.assertIsNone(langbot_sso._normalize_account(""))
        self.assertIsNone(langbot_sso._normalize_account("a" * 101))
        self.assertIsNone(langbot_sso._normalize_account("bad\nname"))
        self.assertIsNone(langbot_sso._normalize_account(123))

    def test_existing_admin_is_rejected(self) -> None:
        self.assertEqual(
            langbot_sso._ERROR_ACCOUNT_REJECTED,
            langbot_sso._check_existing_user(_user(id=1, account="root")),
        )
        self.assertEqual(
            langbot_sso._ERROR_ACCOUNT_REJECTED,
            langbot_sso._check_existing_user(_user(account="Admin")),
        )

    def test_disabled_or_external_users_are_rejected(self) -> None:
        self.assertEqual(
            langbot_sso._ERROR_ACCOUNT_REJECTED,
            langbot_sso._check_existing_user(_user(status=0)),
        )
        self.assertEqual(
            langbot_sso._ERROR_ACCOUNT_REJECTED,
            langbot_sso._check_existing_user(_user(origin=1)),
        )
        self.assertIsNone(langbot_sso._check_existing_user(_user()))

    def test_missing_workspace_is_provisioned(self) -> None:
        user = _user(oid=0)
        session = _FakeSession(membership=None)
        with (
            patch.object(langbot_sso, "_find_user", return_value=user),
            patch.object(settings, "LANGBOT_SSO_DEFAULT_WORKSPACE_ID", 1),
        ):
            resolved, rejection = langbot_sso._resolve_or_create_user(session, "zhangsan")

        self.assertEqual("", rejection)
        self.assertIs(resolved, user)
        self.assertEqual(1, user.oid)
        memberships = [item for item in session.added if isinstance(item, UserWsModel)]
        self.assertEqual(1, len(memberships))
        self.assertEqual(0, memberships[0].weight)

    def test_new_user_is_provisioned_with_a_random_password(self) -> None:
        session = _FakeSession()
        with (
            patch.object(langbot_sso, "_find_user", return_value=None),
            patch.object(settings, "LANGBOT_SSO_DEFAULT_WORKSPACE_ID", 1),
        ):
            user, rejection = langbot_sso._resolve_or_create_user(session, "lisi")

        self.assertEqual("", rejection)
        self.assertIsInstance(user, UserModel)
        self.assertEqual("lisi", user.account)
        self.assertEqual("lisi", user.name)
        self.assertEqual(1, user.oid)
        self.assertEqual(1, user.status)
        self.assertEqual(0, user.origin)
        self.assertEqual(32, len(user.password))
        self.assertTrue(user.email)
        self.assertLessEqual(len(user.email), 100)

    def test_created_user_satisfies_user_info_dto(self) -> None:
        """``/user/info`` validates through ``UserInfoDTO``; email must not be empty."""

        from apps.system.schemas.system_schema import UserInfoDTO

        session = _FakeSession()
        with (
            patch.object(langbot_sso, "_find_user", return_value=None),
            patch.object(settings, "LANGBOT_SSO_DEFAULT_WORKSPACE_ID", 1),
        ):
            user, _ = langbot_sso._resolve_or_create_user(session, "张三")

        info = UserInfoDTO.model_validate(
            {
                "id": 42,
                "account": user.account,
                "name": user.name,
                "email": user.email,
                "status": user.status,
                "origin": user.origin,
                "oid": user.oid,
            }
        )
        self.assertEqual("张三", info.account)

    def test_account_email_prefers_a_real_address(self) -> None:
        self.assertEqual("tester@example.com", langbot_sso._account_email("tester@example.com"))
        self.assertEqual(
            langbot_sso._account_email("张三"),
            langbot_sso._account_email("张三"),
        )
        self.assertNotEqual(
            langbot_sso._account_email("张三"),
            langbot_sso._account_email("李四"),
        )

    def test_existing_user_without_email_is_repaired(self) -> None:
        user = _user(email="")
        session = _FakeSession(membership=None)
        with (
            patch.object(langbot_sso, "_find_user", return_value=user),
            patch.object(settings, "LANGBOT_SSO_DEFAULT_WORKSPACE_ID", 1),
        ):
            resolved, rejection = langbot_sso._resolve_or_create_user(session, "zhangsan")

        self.assertEqual("", rejection)
        self.assertIs(resolved, user)
        self.assertTrue(user.email)
        self.assertIn(user, session.added)

    def test_existing_user_email_is_preserved(self) -> None:
        user = _user(email="kept@example.com")
        session = _FakeSession(membership=None)
        with (
            patch.object(langbot_sso, "_find_user", return_value=user),
            patch.object(settings, "LANGBOT_SSO_DEFAULT_WORKSPACE_ID", 1),
        ):
            langbot_sso._resolve_or_create_user(session, "zhangsan")

        self.assertEqual("kept@example.com", user.email)


class TicketEndpointTest(unittest.IsolatedAsyncioTestCase):
    async def test_ticket_is_issued_and_bound(self) -> None:
        binding_hash = hashlib.sha256(b"browser-binding").hexdigest()
        with _SettingsPatch():
            with patch.object(
                langbot_sso, "_resolve_or_create_user", return_value=(_user(), "")
            ), patch.object(langbot_sso, "clean_user_cache", AsyncMock()):
                response = await langbot_sso.issue_ticket(
                    _signed_request(_payload(binding_hash)), _FakeSession()
                )

            self.assertEqual(200, response.status_code)
            payload = json.loads(response.body)
            self.assertEqual(60, payload["expires_in"])
            ticket_hash = hashlib.sha256(payload["ticket"].encode()).hexdigest()
            self.assertIn(ticket_hash, langbot_sso._ticket_store)
            self.assertEqual(binding_hash, langbot_sso._ticket_store[ticket_hash]["binding_hash"])

    async def test_admin_account_is_rejected(self) -> None:
        with _SettingsPatch():
            with patch.object(
                langbot_sso, "_resolve_or_create_user", return_value=(None, langbot_sso._ERROR_ACCOUNT_REJECTED)
            ):
                response = await langbot_sso.issue_ticket(_signed_request(_payload()), _FakeSession())

        self.assertEqual(403, response.status_code)

    async def test_missing_binding_hash_is_rejected(self) -> None:
        with _SettingsPatch():
            request = _signed_request({"account": "zhangsan"})
            response = await langbot_sso.issue_ticket(request, _FakeSession())

        self.assertEqual(400, response.status_code)


class ExchangeTest(unittest.IsolatedAsyncioTestCase):
    async def _issue(self, binding: str) -> str:
        request = _signed_request(_payload(hashlib.sha256(binding.encode()).hexdigest()))
        with patch.object(langbot_sso, "_resolve_or_create_user", return_value=(_user(), "")), patch.object(
            langbot_sso, "clean_user_cache", AsyncMock()
        ):
            response = await langbot_sso.issue_ticket(request, _FakeSession())
        self.assertEqual(200, response.status_code)
        return json.loads(response.body)["ticket"]

    async def test_exchange_returns_a_usable_token_once(self) -> None:
        with _SettingsPatch():
            ticket = await self._issue("browser-binding")
            request = _FakeRequest(
                json.dumps({"ticket": ticket}).encode(),
                path="/sqlbot/api/v1/system/langbot/sso/exchange",
                cookies={settings.LANGBOT_SSO_BINDING_COOKIE_NAME: "browser-binding"},
            )
            response = await langbot_sso.exchange_ticket(request, _FakeSession(db_user=_user()))

            self.assertEqual(200, response.status_code)
            body = json.loads(response.body)
            self.assertEqual(0, body["code"])
            token = body["data"]["access_token"]
            decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            self.assertEqual(_user().id, decoded["id"])
            self.assertEqual("zhangsan", decoded["account"])
            self.assertEqual(1, decoded["oid"])

            replay = await langbot_sso.exchange_ticket(request, _FakeSession(db_user=_user()))
            self.assertEqual(401, replay.status_code)
            self.assertEqual(langbot_sso._ERROR_TICKET_INVALID, json.loads(replay.body)["code"])

    async def test_wrong_binding_cookie_does_not_consume_the_ticket(self) -> None:
        with _SettingsPatch():
            ticket = await self._issue("browser-binding")
            body = json.dumps({"ticket": ticket}).encode()
            path = "/sqlbot/api/v1/system/langbot/sso/exchange"

            wrong = await langbot_sso.exchange_ticket(
                _FakeRequest(body, path=path, cookies={settings.LANGBOT_SSO_BINDING_COOKIE_NAME: "other"}),
                _FakeSession(db_user=_user()),
            )
            self.assertEqual(401, wrong.status_code)

            right = await langbot_sso.exchange_ticket(
                _FakeRequest(body, path=path, cookies={settings.LANGBOT_SSO_BINDING_COOKIE_NAME: "browser-binding"}),
                _FakeSession(db_user=_user()),
            )
            self.assertEqual(200, right.status_code)

    async def test_missing_cookie_is_rejected(self) -> None:
        with _SettingsPatch():
            ticket = await self._issue("browser-binding")
            response = await langbot_sso.exchange_ticket(
                _FakeRequest(
                    json.dumps({"ticket": ticket}).encode(),
                    path="/sqlbot/api/v1/system/langbot/sso/exchange",
                ),
                _FakeSession(db_user=_user()),
            )

        self.assertEqual(401, response.status_code)

    async def test_expired_ticket_is_rejected(self) -> None:
        with _SettingsPatch():
            ticket = await self._issue("browser-binding")
            ticket_hash = hashlib.sha256(ticket.encode()).hexdigest()
            langbot_sso._ticket_store[ticket_hash]["exp"] = time.time() - 1

            response = await langbot_sso.exchange_ticket(
                _FakeRequest(
                    json.dumps({"ticket": ticket}).encode(),
                    path="/sqlbot/api/v1/system/langbot/sso/exchange",
                    cookies={settings.LANGBOT_SSO_BINDING_COOKIE_NAME: "browser-binding"},
                ),
                _FakeSession(db_user=_user()),
            )

        self.assertEqual(401, response.status_code)

    async def test_disabled_account_cannot_exchange(self) -> None:
        with _SettingsPatch():
            ticket = await self._issue("browser-binding")
            response = await langbot_sso.exchange_ticket(
                _FakeRequest(
                    json.dumps({"ticket": ticket}).encode(),
                    path="/sqlbot/api/v1/system/langbot/sso/exchange",
                    cookies={settings.LANGBOT_SSO_BINDING_COOKIE_NAME: "browser-binding"},
                ),
                _FakeSession(db_user=_user(status=0)),
            )

        self.assertEqual(401, response.status_code)


class TokenPayloadTest(unittest.TestCase):
    def test_issued_payload_matches_the_existing_middleware_schema(self) -> None:
        payload = TokenPayload(id=42, account="zhangsan", oid=1)
        self.assertEqual(42, payload.id)
        self.assertEqual("zhangsan", payload.account)
        self.assertEqual(1, payload.oid)


if __name__ == "__main__":
    unittest.main()
