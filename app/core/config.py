from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "NetSentinel Lab API"
    app_env: str = "development"
    database_url: str = "postgresql+psycopg://netsentinel:netsentinel@db:5432/netsentinel"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


settings = Settings()