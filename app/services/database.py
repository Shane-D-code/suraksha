"""
Database service for PostgreSQL operations.
"""
from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import text
import structlog
import os

from app.config import settings
from app.models.db import Base

logger = structlog.get_logger(__name__)

import asyncpg

# Global engine and session maker
engine = None
async_session_maker = None
db_pool = None


async def init_db():
    """Initialize database connection and create tables."""
    global engine, async_session_maker, db_pool
    
    # Create async engine
    if settings.DEBUG:
        engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEBUG,
            poolclass=NullPool,
        )
    else:
        engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEBUG,
            pool_size=settings.DATABASE_POOL_SIZE,
            max_overflow=settings.DATABASE_MAX_OVERFLOW,
        )
    
    # Create session maker
    async_session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    # Create tables (for development only)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create asyncpg pool for services that need it
    dsn = settings.DATABASE_URL.replace("+asyncpg", "")
    db_pool = await asyncpg.create_pool(dsn)
    
    # Apply graph schema (SQL-based tables)
    await apply_graph_schema()
    
    logger.info("Database initialized", url=settings.DATABASE_URL.split("@")[-1])


async def apply_graph_schema():
    """
    Apply the graph schema SQL for additional tables.
    This creates the graph_nodes, graph_edges, and other tables.
    """
    global engine
    
    if engine is None:
        return
    
    # Read the graph schema SQL file
    schema_path = os.path.join(os.path.dirname(__file__), "graph_schema.sql")
    
    if os.path.exists(schema_path):
        try:
            with open(schema_path, "r") as f:
                schema_sql = f.read()
            
            async with engine.begin() as conn:
                # Execute each statement separately
                for statement in schema_sql.split(";"):
                    statement = statement.strip()
                    if statement:
                        await conn.execute(text(statement))
            
            logger.info("Graph schema applied successfully")
        except Exception as e:
            logger.warning(f"Could not apply graph schema: {e}")
    else:
        logger.debug("Graph schema file not found, skipping")


async def close_db():
    """Close database connection."""
    global engine, db_pool
    if db_pool:
        await db_pool.close()
        db_pool = None
    if engine:
        await engine.dispose()
        logger.info("Database connection closed")


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session for dependency injection."""
    if async_session_maker is None:
        await init_db()
    
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def execute_query(query, params: Optional[dict] = None):
    """Execute a query and return results."""
    if async_session_maker is None:
        await init_db()
    
    async with async_session_maker() as session:
        result = await session.execute(query, params or {})
        return result


async def execute_insert(table, data: dict):
    """Insert data into a table."""
    if async_session_maker is None:
        await init_db()
    
    async with async_session_maker() as session:
        session.add(table(**data))
        await session.commit()


async def execute_update(query, data: dict, params: Optional[dict] = None):
    """Update data in a table."""
    if async_session_maker is None:
        await init_db()
    
    async with async_session_maker() as session:
        await session.execute(query, params or {})
        await session.commit()


async def check_database_health() -> bool:
    """Check if database is healthy."""
    try:
        if async_session_maker is None:
            await init_db()
        
        async with async_session_maker() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        return False
