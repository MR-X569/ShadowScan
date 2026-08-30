import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# OAUTHLIB_INSECURE_TRANSPORT should ONLY be set in development (.env file).
# It must never be hardcoded here. Read from environment variable set externally.
# In production this env var must NOT be set.

from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as users_router
from app.api.v1.scans import router as scans_router
from app.api.v1.admin import router as admin_router
from app.api.v1.ai import router as ai_router

app = FastAPI(
    title="ShadowScan API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "ShadowScan API Running"}


@app.get("/health")
def health():
    """Health check endpoint for deployment monitoring."""
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(users_router)
app.include_router(scans_router)
app.include_router(admin_router)
app.include_router(ai_router)