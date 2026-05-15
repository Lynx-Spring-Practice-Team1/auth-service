from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class SignupRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class SigninRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AccountPreferences(BaseModel):
    order_updates: bool = True
    market_alerts: bool = True
    email_notifications: bool = False
    compact_account_view: bool = False


class UserProfile(BaseModel):
    id: int
    username: str
    email: EmailStr
    created_at: datetime | None = None
    preferences: AccountPreferences


class UserUpdateRequest(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=64)
    email: EmailStr | None = None
    preferences: AccountPreferences | None = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=6)


class MessageResponse(BaseModel):
    message: str
