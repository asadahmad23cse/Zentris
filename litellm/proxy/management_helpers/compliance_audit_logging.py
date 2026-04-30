import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Request

from litellm._logging import verbose_logger
from litellm.proxy._types import UserAPIKeyAuth


def _normalize_action(function_name: str, route_path: str) -> str:
    lowered = function_name.lower()
    if "generate_key" in lowered or "new_" in lowered or "create" in lowered:
        return "Created"
    if "update" in lowered:
        return "Updated"
    if "delete" in lowered or "remove" in lowered:
        return "Deleted"
    if "policy" in route_path:
        return "Policy Updated"
    return function_name.replace("_", " ").title()


def _extract_resource_id_from_payload(payload: Dict[str, Any]) -> Optional[str]:
    resource_id_keys = (
        "resource_id",
        "key",
        "key_id",
        "user_id",
        "team_id",
        "organization_id",
        "project_id",
        "policy_id",
        "model_id",
        "id",
    )
    for key in resource_id_keys:
        value = payload.get(key)
        if value is not None:
            return str(value)
    return None


def _extract_resource_id(request_kwargs: Dict[str, Any]) -> Optional[str]:
    data = request_kwargs.get("data")
    if data is not None:
        if hasattr(data, "model_dump"):
            payload = data.model_dump(exclude_none=True)
        elif isinstance(data, dict):
            payload = data
        else:
            payload = {}
        resource_id = _extract_resource_id_from_payload(payload)
        if resource_id:
            return resource_id

    for key in ("key_id", "user_id", "team_id", "organization_id", "project_id"):
        if key in request_kwargs and request_kwargs[key] is not None:
            return str(request_kwargs[key])
    return None


def is_super_admin(user_api_key_dict: UserAPIKeyAuth) -> bool:
    super_admin_user_ids = {
        user_id.strip()
        for user_id in os.getenv("LITELLM_SUPERADMIN_USER_IDS", "").split(",")
        if user_id.strip()
    }
    super_admin_emails = {
        email.strip().lower()
        for email in os.getenv("LITELLM_SUPERADMIN_EMAILS", "").split(",")
        if email.strip()
    }

    user_id = str(getattr(user_api_key_dict, "user_id", "") or "")
    user_email = str(getattr(user_api_key_dict, "user_email", "") or "").lower()
    return (user_id in super_admin_user_ids) or (user_email in super_admin_emails)


async def create_compliance_audit_log(
    request_kwargs: Dict[str, Any],
    user_api_key_dict: UserAPIKeyAuth,
    function_name: str,
    http_request: Optional[Request],
) -> None:
    try:
        from litellm.proxy.proxy_server import prisma_client

        if prisma_client is None:
            return

        route_path = http_request.url.path if http_request is not None else ""
        ip_address = (
            http_request.client.host
            if http_request is not None and http_request.client is not None
            else "unknown"
        )
        action = _normalize_action(function_name=function_name, route_path=route_path)
        resource_id = _extract_resource_id(request_kwargs=request_kwargs) or "unknown"
        user_id = str(getattr(user_api_key_dict, "user_id", "") or "unknown")

        await prisma_client.db.litellm_complianceauditlog.create(
            data={
                "timestamp": datetime.now(timezone.utc),
                "user_id": user_id,
                "action": action,
                "ip_address": ip_address,
                "resource_id": resource_id,
            }
        )
    except Exception as e:
        verbose_logger.debug("Failed to write compliance audit log: %s", str(e))
