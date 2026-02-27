"""
Authentication and authorization middleware.
"""
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

security = HTTPBearer()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """
    Validate JWT token and return current user.
    
    Args:
        credentials: HTTP Bearer token
    
    Returns:
        User data dictionary
    
    Raises:
        HTTPException: If token is invalid
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    # In production, fetch user from database
    # For MVP, return token payload
    return {
        "user_id": user_id,
        "roles": payload.get("roles", ["user"]),
    }


def require_role(required_roles: List[str]):
    """
    Dependency to require specific roles.
    
    Args:
        required_roles: List of required role names
    
    Returns:
        Dependency function
    
    Raises:
        HTTPException: If user doesn't have required role
    """
    async def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        user_roles = current_user.get("roles", [])
        
        # Check if user has any required role
        if not any(role in user_roles for role in required_roles):
            logger.warning(
                "Insufficient permissions",
                user_id=current_user.get("user_id"),
                required_roles=required_roles,
                user_roles=user_roles,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        
        return current_user
    
    return role_checker


def get_current_active_user(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Get current active user.
    
    Args:
        current_user: Current user from token
    
    Returns:
        User data if active
    
    Raises:
        HTTPException: If user is inactive
    """
    # In production, check if user is active in database
    # For MVP, always return active
    return current_user


def verify_api_key(api_key: str) -> bool:
    """
    Verify API key.
    
    Args:
        api_key: API key to verify
    
    Returns:
        True if valid
    """
    # In production, verify against stored API keys
    # For MVP, simple check
    return api_key == settings.SECRET_KEY
