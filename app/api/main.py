from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes.events import router as events_router
from app.api.routes.health import router as health_router
from app.api.routes.incidents import router as incidents_router
from app.core.config import settings
from app.db.models import Base
from app.db.session import engine


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.3.0",
    lifespan=lifespan,
)


@app.get("/", tags=["root"])
def root():
    return {
        "message": "NetSentinel Lab API is running",
        "docs": "/docs",
        "environment": settings.app_env,
    }


app.include_router(health_router)
app.include_router(events_router)
app.include_router(incidents_router)