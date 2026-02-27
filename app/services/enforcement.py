"""
Enterprise Enforcement Service

This module implements the SEPARATION OF CONCERNS principle:

1. DETECTION LAYER (scoring.py):
   - Returns raw detection scores: model_score, graph_score, etc.
   - Returns risk classification: HIGH, MEDIUM, LOW
   - DOES NOT make blocking decisions

2. ENFORCEMENT LAYER (this file):
   - Takes detection result as input
   - Checks for enterprise overrides FIRST
   - Applies policy mode rules SECOND
   - Returns final block/warn/allow decision

This separation ensures:
- Detection logic remains pure and testable
- Security operators can override detection without corrupting scores
- Policy can be changed without affecting detection accuracy
- Audit trail is maintained for compliance
"""
import re
import uuid
import structlog
from datetime import datetime
from typing import Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db import EnterpriseOverride, PolicySettings, PolicyModeEnum, OverrideActionEnum
from app.models.schemas import RiskLevel

logger = structlog.get_logger(__name__)

# Compiled regex for domain validation
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
)


def validate_domain(domain: str) -> bool:
    """
    Validate domain format.
    
    Args:
        domain: Domain string to validate
        
    Returns:
        True if valid domain format, False otherwise
    """
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_PATTERN.match(domain))


async def get_active_override(
    domain: str, 
    session: AsyncSession
) -> Optional[EnterpriseOverride]:
    """
    Query database for active (non-expired) override for a domain.
    
    Args:
        domain: Domain to look up
        session: Database session
        
    Returns:
        EnterpriseOverride if found and active, None otherwise
    """
    try:
        # Query for override matching domain
        stmt = select(EnterpriseOverride).where(
            and_(
                EnterpriseOverride.domain == domain.lower()
            )
        )
        result = await session.execute(stmt)
        override = result.scalar_one_or_none()
        
        if override is None:
            return None
            
        # Check if override is expired
        if override.expires_at and override.expires_at < datetime.utcnow():
            logger.info("Override expired", domain=domain, override_id=override.id)
            return None
            
        return override
        
    except Exception as e:
        logger.error("Error querying override", domain=domain, error=str(e))
        return None


async def get_policy_mode(session: AsyncSession) -> PolicyModeEnum:
    """
    Get current policy mode from database.
    
    Args:
        session: Database session
        
    Returns:
        PolicyModeEnum value (defaults to BALANCED if not set)
    """
    try:
        stmt = select(PolicySettings).where(PolicySettings.id == 1)
        result = await session.execute(stmt)
        settings = result.scalar_one_or_none()
        
        if settings:
            return settings.policy_mode
            
    except Exception as e:
        logger.error("Error fetching policy mode", error=str(e))
    
    # Default to BALANCED if not configured
    return PolicyModeEnum.BALANCED


async def apply_enforcement_policy(
    domain: str,
    detection_result: dict,
    session: AsyncSession,
    policy_mode: Optional[PolicyModeEnum] = None,
) -> dict:
    """
    Apply enterprise policy and override rules to detection result.
    
    This is the ENFORCEMENT LAYER - it takes detection results and
    applies organizational policy on top.
    
    ARCHITECTURE:
    1. Check for explicit domain override (enterprise allow/block list)
    2. Apply policy mode rules to detection risk level
    3. Return final enforcement decision
    
    Args:
        domain: The domain being scanned
        detection_result: Dict with keys:
            - risk: RiskLevel (HIGH, MEDIUM, LOW)
            - confidence: float
            - reasons: list[str]
            - domain_risk: float
            - content_risk: float
            - known_malicious: bool (optional)
        session: Database session for override lookup
        policy_mode: Override policy mode (optional, fetches from DB if not provided)
        
    Returns:
        Dict with keys:
            - risk: final RiskLevel after enforcement
            - block: bool - whether to block navigation
            - confidence: float - unchanged from detection
            - reasons: list[str] - detection reasons + enforcement reason
            - domain_risk: float - unchanged from detection
            - content_risk: float - unchanged from detection
            - enforcement_action: str - "OVERRIDE_ALLOW", "OVERRIDE_BLOCK", 
                                  "POLICY_BLOCK", "POLICY_WARN", "DEFAULT"
    """
    # Get policy mode if not provided
    if policy_mode is None:
        policy_mode = await get_policy_mode(session)
    
    # Initialize response with detection results (enforcement does NOT modify scores)
    response = {
        "risk": detection_result.get("risk", RiskLevel.LOW),
        "confidence": detection_result.get("confidence", 0.5),
        "reasons": list(detection_result.get("reasons", [])),
        "domain_risk": detection_result.get("domain_risk", 0.0),
        "content_risk": detection_result.get("content_risk", 0.0),
        "block": False,
        "enforcement_action": "DEFAULT",
    }
    
    # ============================================================
    # STEP 1: Check for enterprise override (HIGHEST PRIORITY)
    # ============================================================
    override = await get_active_override(domain, session)
    
    if override:
        logger.info(
            "Enterprise override applied",
            domain=domain,
            action=override.action.value,
            override_id=override.id
        )
        
        if override.action == OverrideActionEnum.ALLOW:
            response["risk"] = RiskLevel.LOW
            response["block"] = False
            response["enforcement_action"] = "OVERRIDE_ALLOW"
            response["reasons"].append(
                f"Enterprise override: explicitly allowed ({override.reason or 'no reason'})"
            )
            
        elif override.action == OverrideActionEnum.BLOCK:
            response["risk"] = RiskLevel.HIGH
            response["block"] = True
            response["enforcement_action"] = "OVERRIDE_BLOCK"
            response["reasons"].append(
                f"Enterprise override: explicitly blocked ({override.reason or 'no reason'})"
            )
        
        return response
    
    # ============================================================
    # STEP 2: Apply policy mode rules
    # ============================================================
    detection_risk = detection_result.get("risk", RiskLevel.LOW)
    known_malicious = detection_result.get("known_malicious", False)
    
    # PERMISSIVE: Block only known_malicious, Warn HIGH, Allow MEDIUM
    if policy_mode == PolicyModeEnum.PERMISSIVE:
        if known_malicious:
            response["risk"] = RiskLevel.HIGH
            response["block"] = True
            response["enforcement_action"] = "POLICY_BLOCK"
            response["reasons"].append("Policy: PERMISSIVE - blocking known malicious")
        elif detection_risk == RiskLevel.HIGH:
            response["enforcement_action"] = "POLICY_WARN"
            response["reasons"].append("Policy: PERMISSIVE - warning on HIGH risk")
        # MEDIUM and LOW are allowed in PERMISSIVE mode
        
    # BALANCED: Block HIGH, Warn MEDIUM
    elif policy_mode == PolicyModeEnum.BALANCED:
        if detection_risk == RiskLevel.HIGH:
            response["block"] = True
            response["enforcement_action"] = "POLICY_BLOCK"
            response["reasons"].append("Policy: BALANCED - blocking HIGH risk")
        elif detection_risk == RiskLevel.MEDIUM:
            response["enforcement_action"] = "POLICY_WARN"
            response["reasons"].append("Policy: BALANCED - warning on MEDIUM risk")
        # LOW is allowed in BALANCED mode
        
    # STRICT: Block HIGH and MEDIUM
    elif policy_mode == PolicyModeEnum.STRICT:
        if detection_risk in (RiskLevel.HIGH, RiskLevel.MEDIUM):
            response["block"] = True
            response["enforcement_action"] = "POLICY_BLOCK"
            if detection_risk == RiskLevel.HIGH:
                response["reasons"].append("Policy: STRICT - blocking HIGH risk")
            else:
                response["reasons"].append("Policy: STRICT - blocking MEDIUM risk")
        # Only LOW is allowed in STRICT mode
    
    logger.info(
        "Enforcement applied",
        domain=domain,
        policy_mode=policy_mode.value,
        detection_risk=detection_risk.value,
        final_risk=response["risk"].value,
        block=response["block"],
        action=response["enforcement_action"]
    )
    
    return response


async def create_override(
    domain: str,
    action: OverrideActionEnum,
    created_by: str,
    reason: Optional[str] = None,
    expires_at: Optional[datetime] = None,
    session: AsyncSession = None,
) -> EnterpriseOverride:
    """
    Create a new enterprise override.
    
    Args:
        domain: Domain to override
        action: ALLOW or BLOCK
        created_by: Username of admin creating override
        reason: Optional reason for override
        expires_at: Optional expiration datetime
        session: Database session
        
    Returns:
        Created EnterpriseOverride object
        
    Raises:
        ValueError: If domain format is invalid
    """
    if not validate_domain(domain):
        raise ValueError(f"Invalid domain format: {domain}")
    
    # Check for existing active override
    existing = await get_active_override(domain, session)
    if existing:
        raise ValueError(f"Active override already exists for domain: {domain}")
    
    override = EnterpriseOverride(
        id=str(uuid.uuid4()),
        domain=domain.lower(),
        action=action,
        reason=reason,
        created_by=created_by,
        expires_at=expires_at,
    )
    
    session.add(override)
    await session.commit()
    await session.refresh(override)
    
    logger.info(
        "Override created",
        override_id=override.id,
        domain=domain,
        action=action.value,
        created_by=created_by
    )
    
    return override


async def delete_override(
    override_id: str,
    session: AsyncSession,
) -> bool:
    """
    Delete an override by ID.
    
    Args:
        override_id: ID of override to delete
        session: Database session
        
    Returns:
        True if deleted, False if not found
    """
    try:
        stmt = select(EnterpriseOverride).where(
            EnterpriseOverride.id == override_id
        )
        result = await session.execute(stmt)
        override = result.scalar_one_or_none()
        
        if override:
            await session.delete(override)
            await session.commit()
            logger.info("Override deleted", override_id=override_id)
            return True
            
    except Exception as e:
        logger.error("Error deleting override", override_id=override_id, error=str(e))
    
    return False


async def update_policy_mode(
    new_mode: PolicyModeEnum,
    updated_by: str,
    session: AsyncSession,
) -> PolicySettings:
    """
    Update the system-wide policy mode.
    
    Args:
        new_mode: New PolicyModeEnum value
        updated_by: Username making the change
        session: Database session
        
    Returns:
        Updated PolicySettings object
    """
    try:
        stmt = select(PolicySettings).where(PolicySettings.id == 1)
        result = await session.execute(stmt)
        settings = result.scalar_one_or_none()
        
        if settings:
            settings.policy_mode = new_mode
            settings.updated_by = updated_by
        else:
            settings = PolicySettings(
                id=1,
                policy_mode=new_mode,
                updated_by=updated_by,
            )
            session.add(settings)
        
        await session.commit()
        await session.refresh(settings)
        
        logger.info("Policy mode updated", new_mode=new_mode.value, updated_by=updated_by)
        return settings
        
    except Exception as e:
        await session.rollback()
        logger.error("Error updating policy mode", error=str(e))
        raise

