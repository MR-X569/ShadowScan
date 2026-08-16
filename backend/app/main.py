from fastapi import FastAPI
from app.models import *

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}