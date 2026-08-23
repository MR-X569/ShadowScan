import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Required for google-auth-oauthlib when running over plain HTTP (localhost dev).
# This MUST be set before any OAuth flow is imported or executed.
os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")

from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as users_router
from app.api.v1.scans import router as scans_router

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
    return {
        "message": "ShadowScan API Running"
    }


app.include_router(auth_router)
app.include_router(users_router)
app.include_router(scans_router)