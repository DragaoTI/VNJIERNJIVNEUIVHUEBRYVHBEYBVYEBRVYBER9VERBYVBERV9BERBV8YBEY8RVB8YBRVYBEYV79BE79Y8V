#!/usr/bin/env python

from fastapi import FastAPI

app = FastAPI(
    title="CrosshairLab API",
    description="API para o aplicativo CrosshairLab",
    version="1.0.0",
)

@app.get("/")
async def root():
    return {"message": "CrosshairLab API", "status": "online"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
