import os
from typing import List


class Settings:
    """
    Application configuration settings.
    Avoids hardcoding environment-dependent variables.
    """
    PROJECT_NAME: str = "AI-Powered IPsec VPN Protocol Analyzer & Security Framework"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"

    # Server settings
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))

    # CORS configuration
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]


settings = Settings()
