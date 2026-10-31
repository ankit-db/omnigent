"""Deterministic push tests: synthetic signing key, mock HTTP, and a private temporary store."""

from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI

from omnigent.db.db_models import current_workspace_id, workspace_scope
from omnigent.runtime import session_stream
from omnigent.server.auth import AuthProvider, UnifiedAuthProvider
from omnigent.server.mobile_apns import APNsConfiguration, APNsResult, APNsTransport
from omnigent.server.mobile_notifications import (
    MobileNotificationService,
    build_mobile_notification_service,
)
from omnigent.server.routes.mobile_notifications import create_mobile_notifications_router


class HeaderAuth(AuthProvider):
    def get_user_id(self, request):
        return request.headers.get("test-user")


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.results = []

    async def send(self, token, payload, **kwargs):
        self.calls.append((token, payload, kwargs))
        return self.results.pop(0) if self.results else APNsResult(accepted=True)

    async def close(self):
        pass


class FakeConversations:
    def __init__(self):
        self.owner = "alice"
        self.archived = False

    def get_conversation(self, sid):
        if sid not in {"conv_a", "conv_child"}:
            return None
        return SimpleNamespace(
            archived=self.archived,
            live_status="running",
            parent_conversation_id="conv_a" if sid == "conv_child" else None,
        )

    def get_session_owner(self, _sid):
        return self.owner if current_workspace_id() == 0 else "bob"


class MobileNotificationsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="omnigent-push-test-")
        path = Path(self.temp.name)
        self.config = APNsConfiguration(
            "TESTTEAM",
            "TESTKEY",
            "ai.omnigent.nativelab",
            "sandbox",
            path / "unused.p8",
            path / "notifications.sqlite",
            "https://example.invalid",
        )
        self.store = FakeConversations()
        self.transport = FakeTransport()
        self.service = MobileNotificationService(
            conversation_store=self.store, config=self.config, transport=self.transport
        )
        self.registration = {
            "installation_id": "install_a",
            "device_token": "ab" * 32,
            "environment": "sandbox",
            "topic": self.config.topic,
            "session_ids": ["conv_a"],
        }
        self.now = time.time()

    async def asyncTearDown(self):
        await self.service.stop()
        self.temp.cleanup()

    def register(self, user="alice", workspace=0, **changes):
        self.service.register(workspace, user, {**self.registration, **changes})

    def event(self, kind="session.status", workspace=0, **data):
        self.service.handle_event(workspace, "conv_a", {"type": kind, **data}, now=self.now)

    def app(self, auth=None):
        app = FastAPI()
        app.include_router(
            create_mobile_notifications_router(
                service=self.service, auth_provider=auth or HeaderAuth()
            ),
            prefix="/v1",
        )
        return app

    async def test_registration_auth_ownership_validation_and_logout(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app()),
            base_url="https://example.invalid",
            headers={"origin": "https://example.invalid"},
        ) as client:
            self.assertEqual(
                (
                    await client.put("/v1/notifications/devices", json=self.registration)
                ).status_code,
                401,
            )
            self.assertEqual(
                (
                    await client.put(
                        "/v1/notifications/devices",
                        json=self.registration,
                        headers={"test-user": "bob"},
                    )
                ).status_code,
                403,
            )
            self.assertEqual(
                (
                    await client.put(
                        "/v1/notifications/devices",
                        json={**self.registration, "device_token": "invalid"},
                        headers={"test-user": "alice"},
                    )
                ).status_code,
                422,
            )
            self.assertEqual(
                (
                    await client.put(
                        "/v1/notifications/devices",
                        json=self.registration,
                        headers={"test-user": "alice", "origin": "https://evil.invalid"},
                    )
                ).status_code,
                403,
            )
            self.assertEqual(
                (
                    await client.put(
                        "/v1/notifications/devices",
                        json=self.registration,
                        headers={"test-user": "alice"},
                    )
                ).status_code,
                204,
            )
            self.assertEqual(
                (
                    await client.put(
                        "/v1/notifications/devices",
                        json={**self.registration, "environment": "production"},
                        headers={"test-user": "alice"},
                    )
                ).status_code,
                409,
            )
            await client.delete(
                "/v1/notifications/devices/install_a", headers={"test-user": "bob"}
            )
            self.event("response.elicitation_request", elicitation_id="first")
            await self.service.flush(now=self.now)
            self.assertEqual(len(self.transport.calls), 1)
            await client.delete(
                "/v1/notifications/devices/install_a", headers={"test-user": "alice"}
            )
            self.event("response.elicitation_request", elicitation_id="second")
            await self.service.flush(now=self.now)
            self.assertEqual(len(self.transport.calls), 1)

    async def test_loopback_requires_all_explicit_boundaries(self):
        self.service.config = replace(
            self.config, server_url="http://127.0.0.1:6767", local_development=True
        )
        self.store.owner = None
        auth = UnifiedAuthProvider(source="header", local_single_user=True)
        for peer, headers, expected in [
            ("127.0.0.1", {}, 204),
            ("::1", {}, 204),
            ("192.168.0.2", {}, 401),
            ("127.0.0.1", {"x-forwarded-for": "127.0.0.1"}, 401),
            ("127.0.0.1", {"forwarded": "for=127.0.0.1"}, 401),
        ]:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=self.app(auth), client=(peer, 1234)),
                base_url="http://127.0.0.1:6767",
                headers={"origin": "http://127.0.0.1:6767"},
            ) as client:
                response = await client.put(
                    "/v1/notifications/devices", json=self.registration, headers=headers
                )
                self.assertEqual(response.status_code, expected, response.text)
        self.service.config = self.config
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app(auth)),
            base_url="http://127.0.0.1:6767",
            headers={"origin": "http://127.0.0.1:6767"},
        ) as client:
            self.assertEqual(
                (
                    await client.put("/v1/notifications/devices", json=self.registration)
                ).status_code,
                401,
            )

    async def test_device_account_conflict_and_workspace_isolation(self):
        self.register()
        with self.assertRaises(ValueError):
            self.register(user="bob", workspace=1)
        self.event("response.elicitation_request", workspace=1, elicitation_id="wrong-workspace")
        await self.service.flush(now=self.now)
        self.assertEqual(self.transport.calls, [])
        self.register(session_ids=["conv_child"])
        with self.assertRaises(PermissionError):
            self.register(session_ids=["conv_missing"])

    async def test_approval_dedupe_and_payload_contains_no_prompt(self):
        self.register()
        for _ in range(2):
            self.event(
                "response.elicitation_request",
                elicitation_id="approval_a",
                params={"message": "private command"},
            )
            await self.service.flush(now=self.now)
        self.assertEqual(len(self.transport.calls), 1)
        _, payload, headers = self.transport.calls[0]
        self.assertEqual(
            payload["omnigent"],
            {
                "version": 1,
                "server_url": self.config.server_url,
                "workspace_id": "0",
                "user_id": "alice",
                "session_id": "conv_a",
                "event_id": payload["omnigent"]["event_id"],
                "kind": "approval",
            },
        )
        self.assertNotIn("private command", json.dumps(payload))
        self.assertLessEqual(len(headers["collapse_id"]), 64)
        self.event(status="idle")
        await self.service.flush(now=self.now + 11)
        self.assertEqual(len(self.transport.calls), 1, "waiting for approval is not completion")

    async def test_completion_settle_cancel_waiting_and_duplicate_idle(self):
        self.register()
        self.event(status="idle")
        await self.service.flush(now=self.now + 9)
        self.assertFalse(self.transport.calls)
        self.event(status="running")
        await self.service.flush(now=self.now + 11)
        self.assertFalse(self.transport.calls)
        self.event(status="waiting")
        await self.service.flush(now=self.now + 11)
        self.assertFalse(self.transport.calls)
        self.event(status="idle")
        self.event(status="idle")
        await self.service.flush(now=self.now + 10)
        await self.service.flush(now=self.now + 20)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.transport.calls[0][1]["omnigent"]["kind"], "completed")
        self.event(status="running")
        self.event(status="failed")
        await self.service.flush(now=self.now + 11)
        self.assertEqual(self.transport.calls[-1][1]["omnigent"]["kind"], "failed")

    async def test_resumed_session_cancels_stale_completion_retry(self):
        self.register()
        self.transport.results = [APNsResult(retryable=True)]
        self.event(status="idle")
        await self.service.flush(now=self.now + 10)
        self.assertEqual(len(self.transport.calls), 1)
        self.event(status="running")
        await self.service.flush(now=self.now + 20)
        self.assertEqual(len(self.transport.calls), 1)

    async def test_background_work_and_resolved_approval_do_not_alert(self):
        self.register()
        self.event(status="idle", background_task_count=1)
        self.event("response.elicitation_request", elicitation_id="approval_a")
        self.event("response.elicitation_resolved", elicitation_id="approval_a")
        await self.service.flush(now=self.now + 11)
        self.assertFalse(self.transport.calls)

    async def test_revoked_ownership_and_archival_rechecked_at_delivery(self):
        self.register()
        self.event(status="idle")
        self.store.owner = "bob"
        await self.service.flush(now=self.now + 11)
        self.assertFalse(self.transport.calls)
        self.store.owner = "alice"
        self.event("response.elicitation_request", elicitation_id="approval_a")
        self.store.archived = True
        await self.service.flush(now=self.now + 11)
        self.assertFalse(self.transport.calls)

    async def test_retry_rotation_invalid_token_and_restart_dedupe(self):
        self.register()
        self.transport.results = [APNsResult(retryable=True), APNsResult(accepted=True)]
        self.event("response.elicitation_request", elicitation_id="approval_a")
        await self.service.flush(now=self.now)
        await self.service.flush(now=self.now + 1)
        self.assertEqual(len(self.transport.calls), 1)
        self.register(device_token="cd" * 32)
        await self.service.flush(now=self.now + 2)
        self.assertEqual(self.transport.calls[-1][0], "cd" * 32)
        self.assertEqual(
            self.transport.calls[0][2]["collapse_id"], self.transport.calls[1][2]["collapse_id"]
        )
        await self.service.stop()
        self.service = MobileNotificationService(
            conversation_store=self.store, config=self.config, transport=self.transport
        )
        self.event("response.elicitation_request", elicitation_id="approval_a")
        await self.service.flush(now=self.now + 5)
        self.assertEqual(len(self.transport.calls), 2)
        self.transport.results = [APNsResult(invalid_token=True)]
        self.event("response.elicitation_request", elicitation_id="approval_b")
        await self.service.flush(now=self.now + 5)
        self.event("response.elicitation_request", elicitation_id="approval_c")
        await self.service.flush(now=self.now + 5)
        self.assertEqual(len(self.transport.calls), 3)

    async def test_lifecycle_observer_without_any_ios_connection(self):
        self.register()
        delivered = asyncio.Event()
        original = self.transport.send

        async def send(*args, **kwargs):
            result = await original(*args, **kwargs)
            delivered.set()
            return result

        self.transport.send = send
        await self.service.start()
        with workspace_scope(0):
            session_stream.publish(
                "conv_a", {"type": "response.elicitation_request", "elicitation_id": "worker_test"}
            )
        await asyncio.wait_for(delivered.wait(), timeout=3)
        self.assertEqual(len(self.transport.calls), 1)
        await self.service.stop()
        session_stream.publish(
            "conv_a", {"type": "response.elicitation_resolved", "elicitation_id": "worker_test"}
        )

    async def test_apns_http_contract_synthetic_signing_and_error_classification(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        statuses = [
            (200, {}),
            (410, {"reason": "Unregistered"}),
            (429, {"reason": "TooManyRequests"}),
            (400, {"reason": "BadTopic"}),
        ]

        def handle(request):
            self.assertEqual(request.url.host, "api.sandbox.push.apple.com")
            self.assertEqual(request.headers["apns-push-type"], "alert")
            self.assertEqual(request.headers["apns-topic"], self.config.topic)
            decoded = jwt.decode(
                request.headers["authorization"].split()[1],
                private_key.public_key(),
                algorithms=["ES256"],
            )
            self.assertEqual(decoded["iss"], "TESTTEAM")
            status, body = statuses.pop(0)
            return httpx.Response(status, json=body)

        transport = APNsTransport(
            self.config, pem, httpx.AsyncClient(transport=httpx.MockTransport(handle))
        )
        expected = [
            APNsResult(accepted=True),
            APNsResult(invalid_token=True),
            APNsResult(retryable=True),
            APNsResult(),
        ]
        for value in expected:
            self.assertEqual(
                await transport.send(
                    "ab" * 32, {"aps": {"alert": "test"}}, collapse_id="fake", expiration=123
                ),
                value,
            )
        await transport.close()

    async def test_default_disabled_no_files_no_provider_and_app_construction(self):
        service = build_mobile_notification_service(conversation_store=self.store, environ={})
        self.assertFalse(service.available)
        await service.start()
        await service.stop()
        from omnigent.server.app import create_app

        with patch.dict("os.environ", {"OMNIGENT_APNS_ENABLED": "0"}):
            app = create_app(
                agent_store=Mock(),
                file_store=Mock(),
                conversation_store=Mock(),
                artifact_store=Mock(),
                agent_cache=Mock(),
            )
        paths = {route.path for route in app.routes if hasattr(route, "path")}
        self.assertIn("/v1/notifications/capabilities", paths)


class APNsConfigurationTests(unittest.TestCase):
    def test_configuration_and_local_development_boundaries(self):
        values = {
            "OMNIGENT_APNS_ENABLED": "1",
            "OMNIGENT_APNS_SINGLE_PROCESS": "1",
            "OMNIGENT_APNS_TEAM_ID": "TEST",
            "OMNIGENT_APNS_KEY_ID": "TEST",
            "OMNIGENT_APNS_TOPIC": "ai.test",
            "OMNIGENT_APNS_ENVIRONMENT": "sandbox",
            "OMNIGENT_APNS_KEY_PATH": "/tmp/not-a-real-key.p8",
            "OMNIGENT_APNS_STORE_PATH": "/tmp/not-created.sqlite",
            "OMNIGENT_APNS_SERVER_URL": "https://example.invalid",
        }
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "invalid.p8"
            key.write_text("not an APNs signing key")
            service = build_mobile_notification_service(
                conversation_store=FakeConversations(),
                environ={
                    **values,
                    "OMNIGENT_APNS_KEY_PATH": str(key),
                    "OMNIGENT_APNS_STORE_PATH": str(Path(directory) / "unused.sqlite"),
                },
            )
            self.assertFalse(service.available)
            self.assertFalse((Path(directory) / "unused.sqlite").exists())
        with patch("importlib.util.find_spec", return_value=object()):
            self.assertIsNotNone(APNsConfiguration.load(values)[0])
            for address in [
                "http://192.168.0.1:6767",
                "http://localhost:6767",
                "http://127.0.0.1.evil.invalid",
                "http://127.0.0.1/path",
            ]:
                self.assertIsNone(
                    APNsConfiguration.load(
                        {
                            **values,
                            "OMNIGENT_APNS_LOCAL_DEVELOPMENT": "1",
                            "OMNIGENT_APNS_SERVER_URL": address,
                        }
                    )[0]
                )
            for address in ["http://127.0.0.1:6767", "http://[::1]:6767"]:
                self.assertIsNotNone(
                    APNsConfiguration.load(
                        {
                            **values,
                            "OMNIGENT_APNS_LOCAL_DEVELOPMENT": "1",
                            "OMNIGENT_APNS_SERVER_URL": address,
                        }
                    )[0]
                )
                self.assertIsNone(
                    APNsConfiguration.load({**values, "OMNIGENT_APNS_SERVER_URL": address})[0]
                )
        self.assertIsNone(APNsConfiguration.load({})[0])


if __name__ == "__main__":
    unittest.main()
