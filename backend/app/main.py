from fastapi import FastAPI

from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as users_router
from app.api.v1.scans import router as scans_router

app = FastAPI(
    title="ShadowScan API",
    version="1.0.0",
)


@app.get("/")
def root():
    return {
        "message": "ShadowScan API Running"
    }


app.include_router(auth_router)
app.include_router(users_router)
app.include_router(scans_router)