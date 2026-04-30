"""
COMPLIANCE CHECK ENDPOINTS

Endpoints for checking regulatory compliance of LLM request logs.

/compliance/eu-ai-act - Check EU AI Act compliance
/compliance/gdpr      - Check GDPR compliance
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
from litellm.proxy.compliance_checks import ComplianceChecker
from litellm.proxy.management_helpers.compliance_audit_logging import is_super_admin
from litellm.proxy.management_helpers.utils import management_endpoint_wrapper
from litellm.types.proxy.compliance_endpoints import (
    ComplianceCheckRequest,
    ComplianceResponse,
)

router = APIRouter()


def _assert_compliance_admin_access(user_api_key_dict: UserAPIKeyAuth) -> None:
    if user_api_key_dict.user_role not in (
        LitellmUserRoles.PROXY_ADMIN,
        LitellmUserRoles.PROXY_ADMIN_VIEW_ONLY,
    ):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied. Admin role required. Current role: {user_api_key_dict.user_role}",
        )


def _serialize_audit_rows(rows: List[Any]) -> List[Dict[str, Any]]:
    return [
        {
            "id": row.id,
            "timestamp": row.timestamp,
            "user_id": row.user_id,
            "action": row.action,
            "ip_address": row.ip_address,
            "resource_id": row.resource_id,
        }
        for row in rows
    ]


@router.post(
    "/compliance/eu-ai-act",
    tags=["compliance"],
    dependencies=[Depends(user_api_key_auth)],
    response_model=ComplianceResponse,
)
@management_endpoint_wrapper
async def check_eu_ai_act_compliance(
    data: ComplianceCheckRequest,
    http_request: Request,
    user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth),
) -> ComplianceResponse:
    """
    Check EU AI Act compliance for a spend log entry.

    Checks:
    - Art. 9: Guardrails applied (any guardrail)
    - Art. 5: Content screened before LLM (pre-call guardrails)
    - Art. 12: Audit record complete (user_id, model, timestamp, guardrail_results)
    """
    checker = ComplianceChecker(data)
    checks = checker.check_eu_ai_act()
    return ComplianceResponse(
        compliant=all(c.passed for c in checks),
        regulation="EU AI Act",
        checks=checks,
    )


@router.post(
    "/compliance/gdpr",
    tags=["compliance"],
    dependencies=[Depends(user_api_key_auth)],
    response_model=ComplianceResponse,
)
@management_endpoint_wrapper
async def check_gdpr_compliance(
    data: ComplianceCheckRequest,
    http_request: Request,
    user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth),
) -> ComplianceResponse:
    """
    Check GDPR compliance for a spend log entry.

    Checks:
    - Art. 32: Data protection applied (pre-call guardrails)
    - Art. 5(1)(c): Sensitive data protected (masked/blocked or no issues)
    - Art. 30: Audit record complete (user_id, model, timestamp, guardrail_results)
    """
    checker = ComplianceChecker(data)
    checks = checker.check_gdpr()
    return ComplianceResponse(
        compliant=all(c.passed for c in checks),
        regulation="GDPR",
        checks=checks,
    )


@router.get(
    "/compliance/audit-logs",
    tags=["compliance"],
    dependencies=[Depends(user_api_key_auth)],
)
@management_endpoint_wrapper
async def get_audit_logs(
    http_request: Request,
    user_id: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    resource_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth),
) -> Dict[str, Any]:
    from litellm.proxy.proxy_server import prisma_client

    _assert_compliance_admin_access(user_api_key_dict=user_api_key_dict)

    if prisma_client is None:
        raise HTTPException(status_code=500, detail="Database not connected")

    where: Dict[str, Any] = {}
    if user_id:
        where["user_id"] = user_id
    if action:
        where["action"] = action
    if resource_id:
        where["resource_id"] = resource_id

    rows = await prisma_client.db.litellm_complianceauditlog.find_many(
        where=where,  # type: ignore
        order={"timestamp": "desc"},
        take=limit,
    )
    return {"logs": _serialize_audit_rows(rows), "count": len(rows)}


@router.get(
    "/compliance/audit-logs/export",
    tags=["compliance"],
    dependencies=[Depends(user_api_key_auth)],
)
@management_endpoint_wrapper
async def export_audit_logs(
    http_request: Request,
    user_id: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    resource_id: Optional[str] = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=10000),
    user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth),
) -> Dict[str, Any]:
    from litellm.proxy.proxy_server import prisma_client

    _assert_compliance_admin_access(user_api_key_dict=user_api_key_dict)

    if not is_super_admin(user_api_key_dict=user_api_key_dict):
        raise HTTPException(
            status_code=403,
            detail="Only SuperAdmin can export audit logs. Configure LITELLM_SUPERADMIN_USER_IDS or LITELLM_SUPERADMIN_EMAILS.",
        )

    if prisma_client is None:
        raise HTTPException(status_code=500, detail="Database not connected")

    where: Dict[str, Any] = {}
    if user_id:
        where["user_id"] = user_id
    if action:
        where["action"] = action
    if resource_id:
        where["resource_id"] = resource_id

    rows = await prisma_client.db.litellm_complianceauditlog.find_many(
        where=where,  # type: ignore
        order={"timestamp": "desc"},
        take=limit,
    )
    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "logs": _serialize_audit_rows(rows),
        "count": len(rows),
    }
