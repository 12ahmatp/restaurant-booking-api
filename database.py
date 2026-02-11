
import os
import hashlib
import secrets
from datetime import datetime

from databases import Database
from sqlalchemy import (
    MetaData,
    Table,
    Column,
    String,
    Integer,
    Boolean,
    Text,
    Date,
    DateTime,
    ForeignKey,
    create_engine,
    text,
)
from sqlalchemy.dialects.postgresql import UUID


# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://dbadmin:YourPasswordHere@restaurant-db-server.postgres.database.azure.com:5432/restaurant_db",
)

database = Database(DATABASE_URL)

metadata = MetaData()


# ---------------------------------------------------------------------------
# SQLAlchemy table definitions
# ---------------------------------------------------------------------------

users = Table(
    "users",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")),
    Column("username", String(50), unique=True, nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("salt", Text, nullable=False),
    Column("role", String(20), nullable=False, server_default="customer"),
    Column("created_at", DateTime, server_default=text("CURRENT_TIMESTAMP")),
)

tables = Table(
    "tables",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")),
    Column("table_number", Integer, unique=True, nullable=False),
    Column("capacity", Integer, nullable=False),
    Column("location", String(20), nullable=False),
    Column("is_available", Boolean, server_default=text("TRUE")),
)

bookings = Table(
    "bookings",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")),
    Column("table_id", UUID(as_uuid=True), ForeignKey("tables.id", ondelete="CASCADE"), nullable=False),
    Column("customer_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("customer_name", String(100), nullable=False),
    Column("date", Date, nullable=False),
    Column("time", String(5), nullable=False),
    Column("guests", Integer, nullable=False),
    Column("status", String(20), server_default="confirmed"),
    Column("created_at", DateTime, server_default=text("CURRENT_TIMESTAMP")),
)


# ---------------------------------------------------------------------------
# Password hashing helpers (matches existing main.py implementation)
# ---------------------------------------------------------------------------

def generate_salt() -> str:
    return secrets.token_hex(32)


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()


# ---------------------------------------------------------------------------
# Initialisation: create enums, tables, constraints, and seed data
# ---------------------------------------------------------------------------

async def initialise_database() -> None:
    """
    Creates all required types, tables, and constraints via raw SQL,
    then seeds sample users and tables if they do not already exist.
    Designed to be called once during application startup.
    """

    # ---- ENUM types (safe to call repeatedly with IF NOT EXISTS) ----------

    await database.execute(
        query="DO $$ BEGIN "
              "IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN "
              "CREATE TYPE user_role AS ENUM ('admin', 'staff', 'customer'); "
              "END IF; END $$;"
    )

    await database.execute(
        query="DO $$ BEGIN "
              "IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'table_location') THEN "
              "CREATE TYPE table_location AS ENUM ('indoor', 'outdoor', 'private_room'); "
              "END IF; END $$;"
    )

    await database.execute(
        query="DO $$ BEGIN "
              "IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'booking_status') THEN "
              "CREATE TYPE booking_status AS ENUM ('confirmed', 'cancelled', 'completed'); "
              "END IF; END $$;"
    )

    # ---- Tables -----------------------------------------------------------

    await database.execute(
        query="""
        CREATE TABLE IF NOT EXISTS users (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            username        VARCHAR(50) UNIQUE NOT NULL,
            password_hash   TEXT NOT NULL,
            salt            TEXT NOT NULL,
            role            VARCHAR(20) NOT NULL DEFAULT 'customer',
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    await database.execute(
        query="""
        CREATE TABLE IF NOT EXISTS tables (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            table_number    INTEGER UNIQUE NOT NULL,
            capacity        INTEGER NOT NULL CHECK (capacity > 0),
            location        VARCHAR(20) NOT NULL,
            is_available    BOOLEAN DEFAULT TRUE
        );
        """
    )

    await database.execute(
        query="""
        CREATE TABLE IF NOT EXISTS bookings (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            table_id        UUID NOT NULL REFERENCES tables(id) ON DELETE CASCADE,
            customer_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            customer_name   VARCHAR(100) NOT NULL,
            date            DATE NOT NULL,
            time            VARCHAR(5) NOT NULL,
            guests          INTEGER NOT NULL CHECK (guests > 0),
            status          VARCHAR(20) DEFAULT 'confirmed',
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # ---- Seed sample users ------------------------------------------------

    seed_users = [
        {"username": "admin",  "password": "admin123", "role": "admin"},
        {"username": "staff1", "password": "staff123", "role": "staff"},
    ]

    for user in seed_users:
        existing = await database.fetch_one(
            query="SELECT id FROM users WHERE username = :username",
            values={"username": user["username"]},
        )
        if existing is None:
            salt = generate_salt()
            password_hash = hash_password(user["password"], salt)
            await database.execute(
                query="""
                INSERT INTO users (username, password_hash, salt, role)
                VALUES (:username, :password_hash, :salt, :role)
                """,
                values={
                    "username": user["username"],
                    "password_hash": password_hash,
                    "salt": salt,
                    "role": user["role"],
                },
            )

    # ---- Seed sample tables -----------------------------------------------

    seed_tables = [
        {"table_number": 1, "capacity": 2, "location": "indoor"},
        {"table_number": 2, "capacity": 4, "location": "indoor"},
        {"table_number": 3, "capacity": 4, "location": "outdoor"},
        {"table_number": 4, "capacity": 6, "location": "outdoor"},
        {"table_number": 5, "capacity": 8, "location": "private_room"},
    ]

    for tbl in seed_tables:
        existing = await database.fetch_one(
            query="SELECT id FROM tables WHERE table_number = :table_number",
            values={"table_number": tbl["table_number"]},
        )
        if existing is None:
            await database.execute(
                query="""
                INSERT INTO tables (table_number, capacity, location)
                VALUES (:table_number, :capacity, :location)
                """,
                values=tbl,
            )
