from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://broker:changeme@postgres:5432/auth_db"
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    internal_service_token: str = "change-me-in-production"

    class Config:
        env_file = ".env"
        env_prefix = ""
        # JWT_SECRET env var maps to jwt_secret field
        fields = {
            "jwt_secret": {"env": "JWT_SECRET"},
            "database_url": {"env": "DATABASE_URL"},
            "internal_service_token": {"env": "INTERNAL_SERVICE_TOKEN"},
        }


settings = Settings()
