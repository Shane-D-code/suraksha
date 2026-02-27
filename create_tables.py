"""
Script to create database tables directly.
"""
import asyncio
from sqlalchemy import create_engine
from app.models.db import Base
from app.config import settings

def create_tables():
    """Create all database tables."""
    # Use sync engine for table creation
    sync_url = settings.DATABASE_URL.replace("+asyncpg", "")
    engine = create_engine(sync_url, echo=True)
    
    print("Creating all tables...")
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully!")
    
    engine.dispose()

if __name__ == "__main__":
    create_tables()
