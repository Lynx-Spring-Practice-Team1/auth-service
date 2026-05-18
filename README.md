# Auth Service

Authentication and user management microservice for the broker platform.

## Overview

Handles user registration, login, JWT-based authentication, profile management, and admin operations (suspension/reactivation). Built with Python/FastAPI and PostgreSQL.

## Tech Stack

- **Python 3.12** + **FastAPI 0.111**
- **PostgreSQL** via SQLAlchemy 2.0 ORM (psycopg2)
- **JWT** (PyJWT) for token auth
- **bcrypt** for password hashing
- **Pydantic v2** for request/response validation
- **uvicorn** ASGI server

## Project Structure

```
auth-service/
├── app/
│   ├── main.py          # FastAPI app, all route handlers
│   ├── auth.py          # JWT generation/verification, password hashing
│   ├── models.py        # SQLAlchemy User model
│   ├── schemas.py       # Pydantic request/response schemas
│   ├── database.py      # DB engine and session management
│   └── config.py        # Settings from environment variables
├── requirements.txt
├── Dockerfile
└── .github/workflows/deploy.yml
```

## API Endpoints

### Public

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/auth/signup` | Register new user, returns JWT |
| `POST` | `/auth/signin` | Login, returns JWT |
| `GET` | `/auth/me` | Get current user profile |
| `PATCH` | `/auth/me` | Update profile (username, email, preferences) |
| `PUT` | `/auth/password` | Change password |

### Internal (require `X-Internal-Token` header)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/internal/admin/users` | List users with filtering and pagination |
| `GET` | `/internal/admin/users/{user_id}` | Get user details |
| `POST` | `/internal/admin/users/{user_id}/suspend` | Suspend a user |
| `POST` | `/internal/admin/users/{user_id}/reactivate` | Reactivate a user |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | **required** | Secret key for JWT signing |
| `DATABASE_URL` | `postgresql://broker:changeme@postgres:5432/auth_db` | PostgreSQL connection string |
| `INTERNAL_SERVICE_TOKEN` | `change-me-in-production` | Token for internal service-to-service calls |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_EXPIRE_MINUTES` | `60` | Token expiration in minutes |

## Getting Started

### Local Development

```bash
# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your values

# Run the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Docker

```bash
docker build -t auth-service .
docker run -p 8000:8000 --env-file .env auth-service
```

## Data Model

**User:**
- `id`, `username` (unique), `email` (unique), `hashed_password`
- `preferences` (JSONB): `order_updates`, `market_alerts`, `email_notifications`, `compact_account_view`
- `is_suspended`, `suspended_reason`, `created_at`

## Deployment

GitHub Actions CI/CD pipeline pushes Docker image to GitHub Container Registry on push to `main`:
```
ghcr.io/lynx-spring-practice-team1/auth-service:latest
```
