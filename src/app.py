import os
import logging
from fastapi import FastAPI  # pyright: ignore[reportMissingImports]

# Configure structured logging for Kubernetes log aggregation
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastAPI with metadata for OpenAPI schema generation
app = FastAPI(
    title="SLSA-Compliant Microservice",
    description="Target application for SBOM and Admission Control testing",
    version="1.0.0"
  )

@app.get("/healthz")
def health_check():
    """Liveness and Readiness probe endpoint for Kubernetes deployments."""
    return {"status": "healthy", "environment": os.getenv("APP_ENV", "local")}

@app.get("/")
def read_root():
    """Main routing endpoint."""
    logger.info("Root endpoint accessed. Service is running securely.")
    return {
        "service": "secure-python-microservice",
        "message": "Traffic allowed. Container provenance verified."
    }