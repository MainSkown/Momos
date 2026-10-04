from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Database
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int = 5432
    
    # Ollama
    OLLAMA_HOST: str
    OLLAMA_PORT: int

    # Upper bound on the num_ctx requested from Ollama for any model, used
    # whenever a project hasn't set its own override (ProjectSettings.
    # max_context_window) - see Agent.changeModel/agent_service.py's
    # _prepare_and_run. 256k covers the native context of essentially every
    # current 8B-class model (e.g. qwen3:8b) without an operator having to
    # raise anything; lower it via .env on hardware that can't afford the
    # KV-cache allocation a very large context implies.
    DEFAULT_MAX_CONTEXT_WINDOW: int = 262144

    # Hard ceiling on how many agent LLM instances may run at once, across
    # the WHOLE backend (every project) - the real hardware constraint
    # (one GPU, limited VRAM) a project's own ProjectSettings.
    # max_concurrent_agents request can never exceed. See agent_service.py's
    # _acquire_agent_slot: effective slots for a project = min(that
    # project's own setting, this value). Same shape/reasoning as
    # DEFAULT_MAX_CONTEXT_WINDOW above - a global default a per-project
    # setting can't override past, lowered via .env on hardware that can
    # only realistically run one model at a time (the actual default this
    # project ships with, since most local setups are exactly that).
    GLOBAL_MAX_CONCURRENT_AGENTS: int = 1

    # Tell Pydantic to look for the .env file in the root directory
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @property
    def database_url(self) -> str:
        """Constructs the SQLAlchemy connection string from env vars."""
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
        
    @property
    def ollama_url(self) -> str:
        return f"http://{self.OLLAMA_HOST}:{self.OLLAMA_PORT}"


settings = Settings()