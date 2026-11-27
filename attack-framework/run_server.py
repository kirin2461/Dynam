#!/usr/bin/env python3
"""Run the Attack Framework API server."""
import uvicorn
from src.api.server import app

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8090)
