"""Single-process native push worker with durable registrations, dedupe, and retry outbox.

The observer runs on the server even when iOS is suspended. SQLite state must live on
a private persistent volume; multi-worker/replica deployment needs a shared outbox.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Mapping
from typing import Any

from jwt.exceptions import PyJWTError

from omnigent.db.db_models import current_workspace_id, workspace_scope
from omnigent.runtime import session_stream
from omnigent.server.mobile_apns import APNsConfiguration, APNsTransport
from omnigent.stores.conversation_store import ConversationStore

_logger = logging.getLogger(__name__)


def _key(*parts: str) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


class MobileNotificationService:
    def __init__(
        self,
        *,
        conversation_store: ConversationStore,
        config: APNsConfiguration | None = None,
        transport: APNsTransport | None = None,
        missing_configuration: list[str] | None = None,
    ) -> None:
        self.config = config
        self._conversations = conversation_store
        self._transport = transport
        self._missing = missing_configuration or []
        self._lock = threading.RLock()
        self._db: sqlite3.Connection | None = None
        self._task: asyncio.Task | None = None
        self._remove_observer = None
        self._queue: asyncio.Queue | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        if config is not None and transport is not None:
            config.store_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(config.store_path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(descriptor)
            os.chmod(config.store_path, 0o600)
            self._db = sqlite3.connect(config.store_path, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    workspace INTEGER, user TEXT, installation TEXT, token TEXT,
                    sessions TEXT, expires REAL, PRIMARY KEY(workspace, user, installation));
                CREATE TABLE IF NOT EXISTS states (
                    workspace INTEGER, session TEXT, value TEXT,
                    PRIMARY KEY(workspace, session));
                CREATE TABLE IF NOT EXISTS outbox (
                    id TEXT PRIMARY KEY, workspace INTEGER, user TEXT, installation TEXT,
                    session TEXT, event TEXT, kind TEXT, expires REAL, next_attempt REAL,
                    attempts INTEGER DEFAULT 0, done INTEGER DEFAULT 0);
            """)

    @property
    def available(self) -> bool:
        return self._db is not None and self._transport is not None

    def capabilities(self) -> dict[str, Any]:
        config = self.config
        return {
            "available": self.available,
            "missing_configuration": self._missing,
            "server_url": config.server_url if config else None,
            "environment": config.environment if config else None,
            "topic": config.topic if config else None,
            "local_development": config.local_development if config else False,
        }

    def _owned(self, workspace: int, user: str, session_id: str) -> bool:
        with workspace_scope(workspace):
            seen = set()
            while session_id not in seen and len(seen) < 64:
                seen.add(session_id)
                conversation = self._conversations.get_conversation(session_id)
                if conversation is None or conversation.archived:
                    return False
                if conversation.parent_conversation_id:
                    session_id = conversation.parent_conversation_id
                else:
                    owner = self._conversations.get_session_owner(session_id)
                    if user == "local" and self.config and self.config.local_development:
                        return workspace == 0 and owner in {None, "local"}
                    return owner == user
        return False

    def register(self, workspace: int, user: str, registration: dict) -> None:
        db = self._db
        if db is None:
            raise ValueError("Push is not configured")
        sessions = sorted(set(registration["session_ids"]))
        if not all(self._owned(workspace, user, sid) for sid in sessions):
            raise PermissionError
        token = registration["device_token"].lower()
        installation = registration["installation_id"]
        with self._lock, db:
            conflict = db.execute(
                "SELECT 1 FROM devices WHERE (installation=? OR token=?) "
                "AND NOT (workspace=? AND user=?) AND expires>?",
                (installation, token, workspace, user, time.time()),
            ).fetchone()
            if conflict:
                raise ValueError("Device already registered")
            db.execute(
                "INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?, ?, ?)",
                (
                    workspace,
                    user,
                    installation,
                    token,
                    json.dumps(sessions),
                    time.time() + 30 * 86400,
                ),
            )
            for sid in sessions:
                with workspace_scope(workspace):
                    conversation = self._conversations.get_conversation(sid)
                status = conversation.live_status if conversation else None
                initial = {
                    "status": status,
                    "run": uuid.uuid4().hex if status in {"running", "waiting"} else None,
                }
                db.execute(
                    "INSERT OR IGNORE INTO states VALUES (?, ?, ?)",
                    (workspace, sid, json.dumps(initial)),
                )

    def unregister(self, workspace: int, user: str, installation: str) -> None:
        if self._db is None:
            return
        with self._lock, self._db:
            self._db.execute(
                "DELETE FROM devices WHERE workspace=? AND user=? AND installation=?",
                (workspace, user, installation),
            )
            self._db.execute(
                "DELETE FROM outbox WHERE workspace=? AND user=? AND installation=?",
                (workspace, user, installation),
            )

    async def start(self) -> None:
        if not self.available or self._task is not None:
            return
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=4096)
        self._remove_observer = session_stream.add_publish_observer(self.observe)
        self._task = asyncio.create_task(self._run(), name="mobile-notifications")

    async def stop(self) -> None:
        if self._remove_observer:
            self._remove_observer()
            self._remove_observer = None
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        self._loop = None
        if self._transport:
            await self._transport.close()
        if self._db:
            self._db.close()
            self._db = None

    def observe(self, session_id: str, event: dict[str, Any]) -> None:
        """Nonblocking, thread-safe callback; capture workspace before crossing event loops."""
        if event.get("type") not in {
            "session.status",
            "response.elicitation_request",
            "response.elicitation_resolved",
        }:
            return
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        workspace = current_workspace_id()
        # Copy just the lifecycle fields. Approval text and tool arguments never enter the outbox.
        data = {
            key: event.get(key)
            for key in ("type", "status", "elicitation_id", "response_id", "background_task_count")
        }

        def enqueue() -> None:
            if self._queue is not None:
                try:
                    self._queue.put_nowait((workspace, session_id, data))
                except asyncio.QueueFull:
                    _logger.warning("Mobile notification event queue is full; event dropped")

        loop.call_soon_threadsafe(enqueue)

    async def _run(self) -> None:
        assert self._queue is not None
        while True:
            try:
                try:
                    workspace, sid, event = await asyncio.wait_for(self._queue.get(), timeout=1)
                    await asyncio.to_thread(self.handle_event, workspace, sid, event)
                except TimeoutError:
                    pass
                # Drain lifecycle changes before considering an idle deadline.
                if self._queue.empty():
                    await self.flush()
            except Exception:  # noqa: BLE001
                _logger.warning("Mobile notification worker failed; will retry")
                await asyncio.sleep(1)

    def handle_event(
        self, workspace: int, session_id: str, event: dict, *, now: float | None = None
    ) -> None:
        """Process the audited flat session.status / response.elicitation_* contracts."""
        db = self._db
        if db is None:
            return
        now = time.time() if now is None else now
        with self._lock, db:
            row = db.execute(
                "SELECT value FROM states WHERE workspace=? AND session=?", (workspace, session_id)
            ).fetchone()
            if row is None:
                return
            state = json.loads(row[0])
            event_type = event.get("type")
            if event_type in {"response.elicitation_request", "response.elicitation_resolved"}:
                elicitation = event.get("elicitation_id")
                if not isinstance(elicitation, str) or not elicitation or len(elicitation) > 512:
                    return
                event_id = _key("approval", elicitation)
                approvals = set(state.get("approvals", []))
                if event_type == "response.elicitation_request":
                    approvals.add(event_id)
                    state.pop("pending", None)
                    self._enqueue(workspace, session_id, event_id, "approval", now)
                else:
                    approvals.discard(event_id)
                    db.execute(
                        "UPDATE outbox SET done=1 WHERE workspace=? AND session=? AND event=?",
                        (workspace, session_id, event_id),
                    )
                state["approvals"] = sorted(approvals)
            elif event_type == "session.status":
                status = event.get("status")
                previous = state.get("status")
                if status in {"running", "waiting", "launching"}:
                    db.execute(
                        "UPDATE outbox SET done=1 WHERE workspace=? AND session=? "
                        "AND kind IN ('completed', 'failed') AND done=0",
                        (workspace, session_id),
                    )
                    if previous not in {"running", "waiting", "launching"}:
                        state["run"] = uuid.uuid4().hex
                    state.pop("pending", None)
                elif status in {"idle", "failed"} and previous in {
                    "running",
                    "waiting",
                    "launching",
                }:
                    # Background work is not a completed turn, even when a harness reports idle.
                    if not event.get("background_task_count") and not state.get("approvals"):
                        run = state.get("run") or event.get("response_id") or uuid.uuid4().hex
                        state["pending"] = {
                            "event": _key("terminal", str(run)),
                            "kind": "failed" if status == "failed" else "completed",
                            "due": now + 10,
                        }
                if status in {"running", "waiting", "launching", "idle", "failed"}:
                    state["status"] = status
            db.execute(
                "UPDATE states SET value=? WHERE workspace=? AND session=?",
                (json.dumps(state), workspace, session_id),
            )

    def _enqueue(
        self, workspace: int, session_id: str, event_id: str, kind: str, now: float
    ) -> None:
        assert self._db is not None
        for device in self._db.execute(
            "SELECT * FROM devices WHERE workspace=? AND expires>?", (workspace, now)
        ):
            if session_id not in json.loads(device["sessions"]):
                continue
            identifier = _key(
                str(workspace), device["user"], device["installation"], session_id, event_id
            )
            self._db.execute(
                "INSERT OR IGNORE INTO outbox "
                "(id,workspace,user,installation,session,event,kind,expires,next_attempt) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    identifier,
                    workspace,
                    device["user"],
                    device["installation"],
                    session_id,
                    event_id,
                    kind,
                    now + 3600,
                    now,
                ),
            )

    async def flush(self, *, now: float | None = None) -> None:
        """Settle terminal edges, deliver due alerts, and bound retry/dedupe retention."""
        db, transport, config = self._db, self._transport, self.config
        if db is None or transport is None or config is None:
            return
        now = time.time() if now is None else now
        with self._lock, db:
            for row in db.execute("SELECT * FROM states").fetchall():
                state = json.loads(row["value"])
                pending = state.get("pending")
                if pending and pending["due"] <= now:
                    self._enqueue(
                        row["workspace"], row["session"], pending["event"], pending["kind"], now
                    )
                    state.pop("pending")
                    db.execute(
                        "UPDATE states SET value=? WHERE workspace=? AND session=?",
                        (json.dumps(state), row["workspace"], row["session"]),
                    )
            db.execute("DELETE FROM devices WHERE expires<=?", (now,))
            db.execute("DELETE FROM outbox WHERE expires<?", (now - 30 * 86400,))
            entries = db.execute(
                "SELECT * FROM outbox WHERE done=0 AND next_attempt<=? AND expires>? LIMIT 100",
                (now, now),
            ).fetchall()
        for entry in entries:
            with self._lock:
                device = db.execute(
                    "SELECT * FROM devices WHERE workspace=? AND user=? AND installation=?",
                    (entry["workspace"], entry["user"], entry["installation"]),
                ).fetchone()
            owned = await asyncio.to_thread(
                self._owned, entry["workspace"], entry["user"], entry["session"]
            )
            if (
                device is None
                or entry["session"] not in json.loads(device["sessions"])
                or not owned
            ):
                with self._lock, db:
                    db.execute("UPDATE outbox SET done=1 WHERE id=?", (entry["id"],))
                continue
            title, body = {
                "approval": ("Agent needs your input", "Open the session to review the request."),
                "completed": ("Agent finished", "Open the session to see the result."),
                "failed": ("Agent stopped", "Open the session to review what happened."),
            }[entry["kind"]]
            payload = {
                "aps": {
                    "alert": {"title": title, "body": body},
                    "sound": "default",
                    "thread-id": _key(
                        config.server_url, str(entry["workspace"]), entry["user"], entry["session"]
                    ),
                },
                "omnigent": {
                    "version": 1,
                    "server_url": config.server_url,
                    "workspace_id": str(entry["workspace"]),
                    "user_id": entry["user"],
                    "session_id": entry["session"],
                    "event_id": entry["event"],
                    "kind": entry["kind"],
                },
            }
            result = await transport.send(
                device["token"], payload, collapse_id=entry["id"], expiration=int(entry["expires"])
            )
            attempts = entry["attempts"] + 1
            with self._lock, db:
                if result.invalid_token:
                    db.execute(
                        "DELETE FROM devices "
                        "WHERE workspace=? AND user=? AND installation=? AND token=?",
                        (
                            entry["workspace"],
                            entry["user"],
                            entry["installation"],
                            device["token"],
                        ),
                    )
                done = result.accepted or not result.retryable or attempts >= 5
                db.execute(
                    "UPDATE outbox SET done=?, attempts=?, next_attempt=? WHERE id=?",
                    (int(done), attempts, now + min(60, 2**attempts), entry["id"]),
                )


def build_mobile_notification_service(
    *, conversation_store: ConversationStore, environ: Mapping[str, str] | None = None
) -> MobileNotificationService:
    config, missing = APNsConfiguration.load(os.environ if environ is None else environ)
    if config is None:
        return MobileNotificationService(
            conversation_store=conversation_store, missing_configuration=missing
        )
    try:
        private_key = config.key_path.read_text()
        # Validate signing before advertising availability; this never contacts Apple.
        import jwt

        jwt.encode(
            {"iss": config.team_id, "iat": int(time.time())},
            private_key,
            algorithm="ES256",
            headers={"kid": config.key_id},
        )
        transport = APNsTransport(config, private_key)
        return MobileNotificationService(
            conversation_store=conversation_store, config=config, transport=transport
        )
    except (OSError, ValueError, ImportError, sqlite3.Error, PyJWTError):
        return MobileNotificationService(
            conversation_store=conversation_store,
            missing_configuration=[
                "Valid APNs ES256 key, HTTP/2 dependency, and writable private notification store"
            ],
        )
