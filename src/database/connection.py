import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Setup logging
logger = logging.getLogger(__name__)

# Connection parameters with environment variable support and sensible defaults
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "netshield_db")

# Construct PostgreSQL DATABASE_URL
# Supports standard PostgreSQL connection URL format
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Fallback to SQLite database file for testing or if PostgreSQL is not available
# This ensures that the application remains functional even in a local dev mode
if os.getenv("USE_SQLITE", "false").lower() == "true":
    DATABASE_URL = "sqlite:///./netshield.db"
    logger.info("Using SQLite database for testing.")
else:
    logger.info(f"Configuring PostgreSQL database connection: postgresql://{DB_USER}:***@{DB_HOST}:{DB_PORT}/{DB_NAME}")

# Create engine
engine = create_engine(
    DATABASE_URL,
    # pool_pre_ping checks connection liveness before executing queries
    pool_pre_ping=True
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative base class for models
Base = declarative_base()

def get_db():
    """Dependency provider that yields a database session and closes it when done."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes database tables by creating them if they do not exist."""
    logger.info("Initializing database tables...")
    try:
        # Import models inside the function to ensure they register on Base.metadata
        from src.database import models
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")
        raise e

if __name__ == "__main__":
    # Force SQLite for self-test to run without needing an active PostgreSQL service
    os.environ["USE_SQLITE"] = "true"
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    init_db()
