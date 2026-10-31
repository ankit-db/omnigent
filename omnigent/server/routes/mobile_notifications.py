"""Authenticated, owner-scoped native device registration. Mount under /v1."""

from __future__ import annotations

import asyncio
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from omnigent.db.db_models import current_workspace_id
from omnigent.server.auth import AuthProvider, UnifiedAuthProvider
from omnigent.server.mobile_notifications import MobileNotificationService

Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,256}$")]


class DeviceRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    installation_id: Identifier
    device_token: str = Field(pattern=r"^(?:[a-fA-F0-9]{2}){16,256}$")
    environment: Literal["sandbox", "production"]
    topic: str = Field(min_length=1, max_length=255)
    session_ids: list[Identifier] = Field(max_length=500)


def create_mobile_notifications_router(
    *, service: MobileNotificationService, auth_provider: AuthProvider | None
) -> APIRouter:
    router = APIRouter(prefix="/notifications")

    def user(request: Request) -> str:
        identity = auth_provider.get_user_id(request) if auth_provider else None
        config = service.config
        local_allowed = (
            config is not None
            and config.local_development
            and isinstance(auth_provider, UnifiedAuthProvider)
            and auth_provider._source == "header"
            and auth_provider._local_single_user
            and request.client is not None
            and request.client.host in {"127.0.0.1", "::1"}
            and request.url.hostname in {"127.0.0.1", "::1"}
            and current_workspace_id() == 0
            and not any(
                name == "forwarded" or name == "x-real-ip" or name.startswith("x-forwarded-")
                for name in request.headers
            )
        )
        if not identity or (identity == "local" and not local_allowed):
            raise HTTPException(401, "Authenticated account required for background notifications")
        if config and config.local_development and identity != "local":
            raise HTTPException(
                403, "Local development push accepts only the local single-user identity"
            )
        # Cookie-authenticated mutations must remain same-origin; native requests omit Origin.
        origin = request.headers.get("origin")
        if request.method != "GET" and origin and origin != str(request.base_url).rstrip("/"):
            raise HTTPException(403, "Cross-origin notification registration is not allowed")
        return identity

    @router.get("/capabilities")
    async def capabilities(request: Request) -> dict:
        user(request)
        return {**service.capabilities(), "workspace_id": str(current_workspace_id())}

    @router.put("/devices", status_code=204)
    async def register(request: Request, body: DeviceRegistration) -> Response:
        identity = user(request)
        if not service.available:
            raise HTTPException(503, "Background notification provider is not configured")
        config = service.config
        assert config is not None
        if body.environment != config.environment or body.topic != config.topic:
            raise HTTPException(409, "APNs environment or app topic does not match this server")
        try:
            await asyncio.to_thread(
                service.register, current_workspace_id(), identity, body.model_dump()
            )
        except PermissionError:
            raise HTTPException(
                403, "Only owned sessions can receive background notifications"
            ) from None
        except ValueError:
            raise HTTPException(
                409, "This device installation belongs to another account"
            ) from None
        return Response(status_code=204)

    @router.delete("/devices/{installation_id}", status_code=204)
    async def unregister(request: Request, installation_id: str) -> Response:
        identity = user(request)
        await asyncio.to_thread(
            service.unregister, current_workspace_id(), identity, installation_id
        )
        return Response(status_code=204)

    return router
