import os
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import asyncpg
import jwt
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional

from sms_service import send_sms


app = FastAPI(
    title="Restaurant Booking System",
    description="A comprehensive REST API for managing restaurant bookings",
    version="1.0.0"
)

security = HTTPBearer()


SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-change-me-in-production")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/restaurant_db")


UTC7 = timezone(timedelta(hours=7))


async def get_connection():
    """Establish and return a database connection"""
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        return conn
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connection failed: {str(e)}"
        )


def hash_password(password: str, salt: str) -> str:
    """Hash password with salt using SHA256"""
    return hashlib.sha256((password + salt).encode()).hexdigest()

def verify_password(password: str, salt: str, password_hash: str) -> bool:
    """Verify password against stored hash"""
    return hash_password(password, salt) == password_hash


def create_access_token(data: dict, expires_minutes: int = 60) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    expire = datetime.now(UTC7) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate JWT token and return current user"""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

    conn = await get_connection()
    try:
        row = await conn.fetchrow(
            "SELECT id, name, email, role, phone FROM users WHERE id = $1",
            user_id
        )
    finally:
        await conn.close()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    return dict(row)


class UserRegister(BaseModel):
    """User registration schema - phone is now REQUIRED"""
    name: str = Field(..., min_length=1, max_length=100, description="User's full name")
    email: str = Field(..., description="User's email address")
    password: str = Field(..., min_length=6, description="User's password (min 6 characters)")
    phone: str = Field(..., min_length=10, max_length=15, description="User's phone number (required for SMS notifications)")

class UserLogin(BaseModel):
    """User login credentials"""
    email: str
    password: str

class RoleUpdate(BaseModel):
    """Update user role (admin only)"""
    role: str = Field(..., description="New role: admin, staff, or customer")

class TableCreate(BaseModel):
    """Create a new table"""
    number: int = Field(..., gt=0, description="Table number (must be unique)")
    capacity: int = Field(..., gt=0, description="Table capacity (number of seats)")
    location: Optional[str] = Field(None, description="Table location (e.g., 'Window side', 'Patio')")

class TableUpdate(BaseModel):
    """Update table details"""
    number: Optional[int] = Field(None, gt=0)
    capacity: Optional[int] = Field(None, gt=0)
    location: Optional[str] = None

class BookingCreate(BaseModel):
    """Create a new booking"""
    table_id: str = Field(..., description="UUID of the table to book")
    date: str = Field(..., description="Booking date (YYYY-MM-DD format)")
    start_time: str = Field(..., description="Start time (HH:MM format)")
    end_time: str = Field(..., description="End time (HH:MM format)")
    guests: int = Field(..., gt=0, description="Number of guests")

class BookingUpdate(BaseModel):
    """Update booking details"""
    table_id: Optional[str] = None
    date: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    guests: Optional[int] = Field(None, gt=0)
    status: Optional[str] = Field(None, description="Booking status: confirmed, cancelled")


@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister):
    """
    Register a new user account.
    Phone number is required for booking SMS notifications.
    """
    conn = await get_connection()
    try:
        # Check if email already exists
        existing = await conn.fetchrow("SELECT id FROM users WHERE email = $1", user.email)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered"
            )

        # Generate user ID and password hash
        user_id = str(uuid.uuid4())
        salt = secrets.token_hex(16)
        password_hash = hash_password(user.password, salt)

        # Insert new user
        await conn.execute(
            """
            INSERT INTO users (id, name, email, password_hash, salt, role, phone)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            user_id, user.name, user.email, password_hash, salt, "customer", user.phone
        )

        return {
            "id": user_id,
            "name": user.name,
            "email": user.email,
            "role": "customer",
            "phone": user.phone,
            "message": "Registration successful"
        }
    finally:
        await conn.close()


@app.post("/login")
async def login(credentials: UserLogin):
    """
    Authenticate user and return JWT access token
    """
    conn = await get_connection()
    try:
        row = await conn.fetchrow(
            "SELECT id, name, email, password_hash, salt, role FROM users WHERE email = $1",
            credentials.email,
        )
    finally:
        await conn.close()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    if not verify_password(credentials.password, row["salt"], row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Generate JWT token
    token = create_access_token({"user_id": row["id"], "role": row["role"]})

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "role": row["role"],
        },
    }


@app.get("/users/me")
async def get_me(user=Depends(get_current_user)):
    """
    Get current authenticated user's profile
    """
    return user


@app.get("/users")
async def list_users(user=Depends(get_current_user)):
    """
    List all users (admin access only)
    """
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    conn = await get_connection()
    try:
        rows = await conn.fetch(
            "SELECT id, name, email, role, phone FROM users ORDER BY name"
        )
    finally:
        await conn.close()

    return [dict(r) for r in rows]


@app.put("/users/{user_id}/role")
async def update_user_role(user_id: str, body: RoleUpdate, user=Depends(get_current_user)):
    """
    Update a user's role (admin access only)
    Valid roles: admin, staff, customer
    """
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    if body.role not in ("admin", "staff", "customer"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be admin, staff, or customer"
        )

    conn = await get_connection()
    try:
        result = await conn.execute(
            "UPDATE users SET role = $1 WHERE id = $2",
            body.role, user_id
        )
        if result == "UPDATE 0":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
    finally:
        await conn.close()

    return {"message": f"User {user_id} role updated to {body.role}"}


@app.get("/tables")
async def list_tables(user=Depends(get_current_user)):
    """
    Get list of all restaurant tables
    """
    conn = await get_connection()
    try:
        rows = await conn.fetch(
            "SELECT id, number, capacity, location FROM tables ORDER BY number"
        )
    finally:
        await conn.close()

    return [dict(r) for r in rows]


@app.post("/tables", status_code=status.HTTP_201_CREATED)
async def create_table(table: TableCreate, user=Depends(get_current_user)):
    """
    Create a new table (admin or staff access required)
    """
    if user["role"] not in ("admin", "staff"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or staff access required"
        )

    conn = await get_connection()
    try:
        # Check if table number already exists
        existing = await conn.fetchrow(
            "SELECT id FROM tables WHERE number = $1",
            table.number
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Table number already exists"
            )

        table_id = str(uuid.uuid4())
        await conn.execute(
            "INSERT INTO tables (id, number, capacity, location) VALUES ($1, $2, $3, $4)",
            table_id, table.number, table.capacity, table.location,
        )

        return {
            "id": table_id,
            "number": table.number,
            "capacity": table.capacity,
            "location": table.location,
        }
    finally:
        await conn.close()


@app.put("/tables/{table_id}")
async def update_table(table_id: str, table: TableUpdate, user=Depends(get_current_user)):
    """
    Update table details (admin or staff access required)
    """
    if user["role"] not in ("admin", "staff"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or staff access required"
        )

    # Build dynamic update query
    fields = {}
    if table.number is not None:
        fields["number"] = table.number
    if table.capacity is not None:
        fields["capacity"] = table.capacity
    if table.location is not None:
        fields["location"] = table.location

    if not fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update"
        )

    set_clauses = []
    values = []
    idx = 1
    for col, val in fields.items():
        set_clauses.append(f"{col} = ${idx}")
        values.append(val)
        idx += 1

    values.append(table_id)
    query = f"UPDATE tables SET {', '.join(set_clauses)} WHERE id = ${idx}"

    conn = await get_connection()
    try:
        result = await conn.execute(query, *values)
        if result == "UPDATE 0":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Table not found"
            )
    finally:
        await conn.close()

    return {"message": f"Table {table_id} updated successfully"}


@app.delete("/tables/{table_id}")
async def delete_table(table_id: str, user=Depends(get_current_user)):
    """
    Delete a table (admin access only)
    """
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    conn = await get_connection()
    try:
        result = await conn.execute("DELETE FROM tables WHERE id = $1", table_id)
        if result == "DELETE 0":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Table not found"
            )
    finally:
        await conn.close()

    return {"message": f"Table {table_id} deleted successfully"}


async def check_booking_conflict(
    conn,
    table_id: str,
    date: str,
    start_time: str,
    end_time: str,
    exclude_booking_id: str = None
):
    """
    Check if a booking conflicts with existing bookings for the same table
    """
    query = """
        SELECT id FROM bookings
        WHERE table_id = $1
          AND date = $2
          AND start_time < $3
          AND end_time > $4
          AND status != 'cancelled'
    """
    values = [table_id, date, end_time, start_time]

    if exclude_booking_id:
        query += " AND id != $5"
        values.append(exclude_booking_id)

    conflict = await conn.fetchrow(query, *values)
    return conflict


@app.get("/bookings")
async def list_bookings(user=Depends(get_current_user)):
    """
    List bookings:
    - Admin/Staff: See all bookings
    - Customer: See only their own bookings
    """
    conn = await get_connection()
    try:
        if user["role"] in ("admin", "staff"):
            # Admin/Staff see all bookings
            rows = await conn.fetch(
                """
                SELECT b.id, b.user_id, b.table_id, b.date, b.start_time, b.end_time,
                       b.guests, b.status, b.created_at, u.name AS user_name, t.number AS table_number
                FROM bookings b
                JOIN users u ON b.user_id = u.id
                JOIN tables t ON b.table_id = t.id
                ORDER BY b.date DESC, b.start_time
                """
            )
        else:
            # Customers see only their bookings
            rows = await conn.fetch(
                """
                SELECT b.id, b.user_id, b.table_id, b.date, b.start_time, b.end_time,
                       b.guests, b.status, b.created_at, t.number AS table_number
                FROM bookings b
                JOIN tables t ON b.table_id = t.id
                WHERE b.user_id = $1
                ORDER BY b.date DESC, b.start_time
                """,
                user["id"],
            )
    finally:
        await conn.close()

    return [dict(r) for r in rows]


@app.post("/bookings", status_code=status.HTTP_201_CREATED)
async def create_booking(booking: BookingCreate, user=Depends(get_current_user)):
    """
    Create a new table booking with automatic conflict detection and SMS notification
    """
    conn = await get_connection()
    try:
        # Verify the table exists
        table_row = await conn.fetchrow(
            "SELECT id, number, capacity FROM tables WHERE id = $1",
            booking.table_id
        )
        if not table_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Table not found"
            )

        # Validate guest count against table capacity
        if booking.guests > table_row["capacity"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Table capacity is {table_row['capacity']}, but {booking.guests} guests requested"
            )

        # Check for time conflicts
        conflict = await check_booking_conflict(
            conn,
            booking.table_id,
            booking.date,
            booking.start_time,
            booking.end_time
        )
        if conflict:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Time conflict with existing booking {conflict['id']}",
            )

        booking_id = str(uuid.uuid4())
        created_at = datetime.now(UTC7).isoformat()

        await conn.execute(
            """
            INSERT INTO bookings (id, user_id, table_id, date, start_time, end_time, guests, status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            booking_id, user["id"], booking.table_id, booking.date,
            booking.start_time, booking.end_time, booking.guests, "confirmed", created_at,
        )

        # Fetch user phone for SMS (phone is now guaranteed to exist)
        user_row = await conn.fetchrow(
            "SELECT name, phone FROM users WHERE id = $1",
            user["id"]
        )
    finally:
        await conn.close()

    # Send SMS notification
    if user_row and user_row["phone"]:
        try:
            await send_sms(
                phone_number=user_row["phone"],
                message=(
                    f"Hi {user_row['name']}! Your booking is confirmed.\n"
                    f"Table: {table_row['number']}\n"
                    f"Date: {booking.date}\n"
                    f"Time: {booking.start_time} - {booking.end_time}\n"
                    f"Guests: {booking.guests}\n"
                    f"Booking ID: {booking_id}\n"
                    f"Thank you for choosing us!"
                ),
            )
        except Exception as e:
            # Log error but don't fail the booking
            print(f"SMS notification failed on create: {e}")

    return {
        "id": booking_id,
        "user_id": user["id"],
        "table_id": booking.table_id,
        "table_number": table_row["number"],
        "date": booking.date,
        "start_time": booking.start_time,
        "end_time": booking.end_time,
        "guests": booking.guests,
        "status": "confirmed",
        "created_at": created_at,
    }


@app.put("/bookings/{booking_id}")
async def update_booking(booking_id: str, booking: BookingUpdate, user=Depends(get_current_user)):
    """
    Update an existing booking with conflict detection
    """
    conn = await get_connection()
    try:
        # Fetch existing booking
        existing = await conn.fetchrow("SELECT * FROM bookings WHERE id = $1", booking_id)
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Booking not found"
            )

        # Ownership check (customers can only update their own bookings)
        if user["role"] not in ("admin", "staff") and existing["user_id"] != user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update your own bookings"
            )

        # Build dynamic update
        fields = {}
        if booking.table_id is not None:
            fields["table_id"] = booking.table_id
        if booking.date is not None:
            fields["date"] = booking.date
        if booking.start_time is not None:
            fields["start_time"] = booking.start_time
        if booking.end_time is not None:
            fields["end_time"] = booking.end_time
        if booking.guests is not None:
            fields["guests"] = booking.guests
        if booking.status is not None:
            # Validate status
            if booking.status not in ("confirmed", "cancelled"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid status. Must be 'confirmed' or 'cancelled'"
                )
            fields["status"] = booking.status

        if not fields:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields to update"
            )

        # Check conflicts if table, date, or time changed
        check_table = fields.get("table_id", existing["table_id"])
        check_date = fields.get("date", existing["date"])
        check_start = fields.get("start_time", existing["start_time"])
        check_end = fields.get("end_time", existing["end_time"])

        if any(k in fields for k in ("table_id", "date", "start_time", "end_time")):
            conflict = await check_booking_conflict(
                conn,
                check_table,
                check_date,
                check_start,
                check_end,
                exclude_booking_id=booking_id
            )
            if conflict:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Time conflict with existing booking {conflict['id']}",
                )

        # Execute dynamic update
        set_clauses = []
        values = []
        idx = 1
        for col, val in fields.items():
            set_clauses.append(f"{col} = ${idx}")
            values.append(val)
            idx += 1

        values.append(booking_id)
        query = f"UPDATE bookings SET {', '.join(set_clauses)} WHERE id = ${idx}"
        await conn.execute(query, *values)

        # Fetch booking owner's phone
        owner_id = existing["user_id"]
        user_row = await conn.fetchrow(
            "SELECT name, phone FROM users WHERE id = $1",
            owner_id
        )
    finally:
        await conn.close()

    # Send SMS notification
    if user_row and user_row["phone"]:
        try:
            await send_sms(
                phone_number=user_row["phone"],
                message=(
                    f"Hi {user_row['name']}, your booking {booking_id} has been updated.\n"
                    f"Please check the app for the latest details."
                ),
            )
        except Exception as e:
            print(f"SMS notification failed on update: {e}")

    return {"message": f"Booking {booking_id} updated successfully"}


@app.delete("/bookings/{booking_id}")
async def delete_booking(booking_id: str, user=Depends(get_current_user)):
    """
    Delete/cancel a booking with SMS notification
    """
    conn = await get_connection()
    try:
        existing = await conn.fetchrow("SELECT * FROM bookings WHERE id = $1", booking_id)
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Booking not found"
            )

        # Ownership check
        if user["role"] not in ("admin", "staff") and existing["user_id"] != user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete your own bookings"
            )

        await conn.execute("DELETE FROM bookings WHERE id = $1", booking_id)

        # Fetch booking owner's phone
        owner_id = existing["user_id"]
        user_row = await conn.fetchrow(
            "SELECT name, phone FROM users WHERE id = $1",
            owner_id
        )
    finally:
        await conn.close()

    # Send SMS notification
    if user_row and user_row["phone"]:
        try:
            await send_sms(
                phone_number=user_row["phone"],
                message=(
                    f"Hi {user_row['name']}, your booking {booking_id} "
                    f"on {existing['date']} ({existing['start_time']} - {existing['end_time']}) "
                    f"has been cancelled."
                ),
            )
        except Exception as e:
            print(f"SMS notification failed on delete: {e}")

    return {"message": f"Booking {booking_id} cancelled successfully"}


@app.get("/")
async def root():
    """API health check"""
    return {
        "status": "online",
        "service": "Restaurant Booking System API",
        "version": "1.0.0",
        "documentation": "/docs"
    }


@app.on_event("startup")
async def startup_event():
    """Run checks on startup"""
    print("🚀 Restaurant Booking System API is starting...")
    print(f"📍 Timezone: UTC+7")
    print(f"🔐 Secret Key: {'✓ Set' if SECRET_KEY != 'default-secret-change-me-in-production' else '⚠️  Using default (change in production!)'}")
    print(f"🗄️  Database URL: {DATABASE_URL[:30]}...")
    
    # Test database connection
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        await conn.close()
        print("✅ Database connection successful")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)