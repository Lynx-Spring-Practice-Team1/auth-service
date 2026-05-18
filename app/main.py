import json

from fastapi import FastAPI, Depends, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import inspect, or_, text
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.database import engine, get_db
from app.models import Base, User
from app.schemas import (
    AccountPreferences,
    MessageResponse,
    PasswordChangeRequest,
    SigninRequest,
    SignupRequest,
    TokenResponse,
    UserProfile,
    UserUpdateRequest,
)
from app.auth import create_access_token, get_current_user_id, hash_password, verify_password

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Auth Service")

DEFAULT_PREFERENCES = AccountPreferences().model_dump()


def default_preferences() -> dict:
    return dict(DEFAULT_PREFERENCES)


def normalize_preferences(value: dict | None) -> dict:
    return AccountPreferences(**(value or {})).model_dump()


def ensure_preferences_column() -> None:
    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("users")}
    if "preferences" in columns:
        return

    serialized = json.dumps(default_preferences())
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(
                text(
                    "ALTER TABLE users "
                    "ADD COLUMN IF NOT EXISTS preferences JSONB NOT NULL "
                    f"DEFAULT '{serialized}'::jsonb"
                )
            )
        else:
            conn.execute(
                text(
                    "ALTER TABLE users "
                    f"ADD COLUMN preferences JSON NOT NULL DEFAULT '{serialized}'"
                )
            )


def ensure_suspension_columns() -> None:
    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("users")}
    with engine.begin() as conn:
        if "is_suspended" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN is_suspended BOOLEAN NOT NULL DEFAULT false"))
        if "suspended_reason" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN suspended_reason VARCHAR(500)"))


ensure_preferences_column()
ensure_suspension_columns()


def require_internal_token(
    x_internal_token: str | None = Header(default=None, alias="X-Internal-Token"),
) -> None:
    if x_internal_token != settings.internal_service_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid internal token")


def to_user_profile(user: User) -> UserProfile:
    return UserProfile(
        id=user.id,
        username=user.username,
        email=user.email,
        created_at=user.created_at,
        preferences=AccountPreferences(**normalize_preferences(user.preferences)),
    )


def get_current_user(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user


@app.get("/health")
def health():
    return {"status": "ok", "service": "auth-service"}


@app.post("/auth/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def signup(body: SignupRequest, db: Session = Depends(get_db)):
    user = User(
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
        preferences=default_preferences(),
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Registration processed. If this is a new account, please sign in."},
        )
    return TokenResponse(access_token=create_access_token(user.id))


@app.post("/auth/signin", response_model=TokenResponse)
def signin(body: SigninRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return TokenResponse(access_token=create_access_token(user.id))


@app.get("/auth/me", response_model=UserProfile)
def get_me(user: User = Depends(get_current_user)):
    return to_user_profile(user)


@app.patch("/auth/me", response_model=UserProfile)
def update_me(
    body: UserUpdateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if body.username is not None:
        user.username = body.username.strip()
        if not user.username:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Username is required")

    if body.email is not None:
        user.email = str(body.email)

    if body.preferences is not None:
        user.preferences = body.preferences.model_dump()

    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email already taken")

    return to_user_profile(user)


@app.put("/auth/password", response_model=MessageResponse)
def change_password(
    body: PasswordChangeRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    user.hashed_password = hash_password(body.new_password)
    db.commit()
    return MessageResponse(message="Password updated")


def _user_to_admin_dict(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "is_suspended": bool(user.is_suspended),
        "suspended_reason": user.suspended_reason,
    }


@app.get("/internal/admin/users")
def admin_list_users(
    _: None = Depends(require_internal_token),
    q: str | None = Query(default=None),
    status_filter: str = Query(default="all", alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(User)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.username.ilike(like), User.email.ilike(like)))
    if status_filter == "active":
        query = query.filter(User.is_suspended == False)  # noqa: E712
    elif status_filter == "suspended":
        query = query.filter(User.is_suspended == True)  # noqa: E712
    total = query.count()
    users = query.order_by(User.id).offset(offset).limit(limit).all()
    return {"items": [_user_to_admin_dict(u) for u in users], "total": total, "limit": limit, "offset": offset}


@app.get("/internal/admin/users/{user_id}")
def admin_get_user(
    user_id: int,
    _: None = Depends(require_internal_token),
    db: Session = Depends(get_db),
) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return _user_to_admin_dict(user)


class AdminSuspendRequest(BaseModel):
    reason: str | None = None


@app.post("/internal/admin/users/{user_id}/suspend")
def admin_suspend_user(
    user_id: int,
    body: AdminSuspendRequest,
    _: None = Depends(require_internal_token),
    db: Session = Depends(get_db),
) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.is_suspended = True
    user.suspended_reason = body.reason
    db.commit()
    return _user_to_admin_dict(user)


@app.post("/internal/admin/users/{user_id}/reactivate")
def admin_reactivate_user(
    user_id: int,
    _: None = Depends(require_internal_token),
    db: Session = Depends(get_db),
) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.is_suspended = False
    user.suspended_reason = None
    db.commit()
    return _user_to_admin_dict(user)
