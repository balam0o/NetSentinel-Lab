from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "NetSentinel Lab API"
    app_env: str = "development"
    database_url: str

    correlation_window_hours: int = 24
    medium_burst_threshold: int = 3
    medium_burst_window_minutes: int = 15
    attack_chain_window_minutes: int = 10

    netsentinel_api_key: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    @property
    def sqlalchemy_database_url(self) -> str:
        if self.database_url.startswith("postgresql://"):
            return self.database_url.replace("postgresql://", "postgresql+psycopg://", 1)
        return self.database_url


settings = Settings()