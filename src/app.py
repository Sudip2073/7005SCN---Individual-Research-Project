from fastapi import FastAPI
import os

app = FastAPI(title="Secure-Supply-Chain-Target")

@app.get("/healthz")
def health_check():
    return {"status": "healthy", "environment": os.getenv("APP_ENV", "local")}

@app.get("/")
def read_root():
    return {"message": "Secured via SLSA Co-sign & Kyverno"}