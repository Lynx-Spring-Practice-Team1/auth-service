import json

from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

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


ensure_preferences_column()


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
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email already taken")
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
