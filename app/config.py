import os

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+asyncpg://app_user:app_password@localhost:5432/app_db"
)
SECRET_KEY = os.environ.get("SECRET_KEY", "gfdmhghif38yrf9ew0jkf32")
