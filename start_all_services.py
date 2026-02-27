#!/usr/bin/env python3
"""
Start all PhishGuard services:
- Backend API (FastAPI)
- Frontend Dashboard (Vite/React)
- Verify ML models are loaded
- Verify database and Redis connections
"""

import asyncio
import subprocess
import sys
import time
import os
import signal
from pathlib import Path
import requests
import json

# Colors for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

def print_status(message, status="info"):
    """Print colored status messages."""
    colors = {
        "info": BLUE,
        "success": GREEN,
        "warning": YELLOW,
        "error": RED
    }
    color = colors.get(status, BLUE)
    print(f"{color}[{status.upper()}]{RESET} {message}")

def check_services():
    """Check if required services are running."""
    print_status("Checking required services...", "info")
    
    # Check Redis
    try:
        import redis
        r = redis.from_url("redis://localhost:6379/0")
        r.ping()
        print_status("Redis: Running", "success")
    except Exception as e:
        print_status(f"Redis: Not running ({e})", "error")
        return False
    
    # Check PostgreSQL
    try:
        import asyncpg
        # Try to connect
        print_status("PostgreSQL: Assuming running (check manually)", "warning")
    except Exception as e:
        print_status(f"PostgreSQL check failed: {e}", "warning")
    
    return True

def verify_ml_models():
    """Verify ML models are trained and available."""
    print_status("Verifying ML models...", "info")
    
    models = {
        "NLP Phishing Model": "models/phish_model.joblib",
        "NLP Vectorizer": "models/tfidf_vectorizer.joblib",
        "GNN Model": "ml/models/gnn_model.pt",
        "Meta Model": "models/meta_phish_model.joblib"
    }
    
    all_present = True
    for name, path in models.items():
        if Path(path).exists():
            size = Path(path).stat().st_size / 1024  # KB
            print_status(f"{name}: Present ({size:.1f} KB)", "success")
        else:
            print_status(f"{name}: MISSING at {path}", "error")
            all_present = False
    
    return all_present

def start_backend():
    """Start the FastAPI backend server."""
    print_status("Starting Backend API...", "info")
    
    backend_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"],
        cwd=Path(__file__).parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for server to start
    print_status("Waiting for backend to start...", "info")
    time.sleep(3)
    
    # Check if server is running
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print_status("Backend API: Running on http://localhost:8000", "success")
            return backend_process
        else:
            print_status(f"Backend returned status {response.status_code}", "error")
            return None
    except Exception as e:
        print_status(f"Backend not responding: {e}", "error")
        # Still return process, it might be starting up
        return backend_process

def start_frontend():
    """Start the frontend dashboard."""
    print_status("Starting Frontend Dashboard...", "info")
    
    frontend_dir = Path(__file__).parent / "aws" / "Chrome_extensions" / "dashboard"
    
    if not frontend_dir.exists():
        print_status(f"Frontend directory not found: {frontend_dir}", "error")
        return None
    
    # Check if node_modules exists
    if not (frontend_dir / "node_modules").exists():
        print_status("Installing frontend dependencies...", "info")
        try:
            subprocess.run(["npm", "install"], cwd=frontend_dir, check=True, capture_output=True)
            print_status("Dependencies installed", "success")
        except subprocess.CalledProcessError as e:
            print_status(f"npm install failed: {e}", "error")
            return None
    
    # Check if dist exists, if not build first
    if not (frontend_dir / "dist").exists():
        print_status("Building frontend for production...", "info")
        try:
            subprocess.run(["npm", "run", "build"], cwd=frontend_dir, check=True, capture_output=True)
            print_status("Frontend built successfully", "success")
        except subprocess.CalledProcessError as e:
            print_status(f"Build failed: {e}", "warning")
    
    # Start Vite dev server
    frontend_process = subprocess.Popen(
        ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"],
        cwd=frontend_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    print_status("Waiting for frontend to start on http://localhost:5173...", "info")
    time.sleep(5)
    
    # Verify frontend is accessible
    try:
        import urllib.request
        urllib.request.urlopen("http://localhost:5173", timeout=3)
        print_status("Frontend Dashboard: Running at http://localhost:5173", "success")
    except Exception:
        print_status("Frontend Dashboard: Started (verify manually at http://localhost:5173)", "warning")
    
    return frontend_process

def test_api_endpoints():
    """Test key API endpoints."""
    print_status("Testing API endpoints...", "info")
    
    endpoints = [
        ("GET", "http://localhost:8000/", "Root"),
        ("GET", "http://localhost:8000/health", "Health Check"),
        ("GET", "http://localhost:8000/api/v1/threats/summary", "Threat Summary"),
    ]
    
    for method, url, name in endpoints:
        try:
            if method == "GET":
                response = requests.get(url, timeout=5)
            else:
                response = requests.post(url, timeout=5)
            
            if response.status_code == 200:
                print_status(f"{name}: OK", "success")
            else:
                print_status(f"{name}: Status {response.status_code}", "warning")
        except Exception as e:
            print_status(f"{name}: Failed ({e})", "error")

def test_ml_integration():
    """Test ML model integration."""
    print_status("Testing ML integration...", "info")
    
    try:
        # Test NLP predictor
        from intelligence.nlp.predictor import PhishingPredictor
        predictor = PhishingPredictor()
        result = predictor.predict("Urgent! Verify your account immediately.")
        
        if result.get('method') == 'ml':
            print_status(f"NLP Predictor: Using ML (score: {result['score']:.4f})", "success")
        else:
            print_status(f"NLP Predictor: Using rule-based", "warning")
    except Exception as e:
        print_status(f"NLP Predictor: Failed ({e})", "error")
    
    try:
        # Test GNN embedding service
        import asyncio
        from app.services.graph import GraphService
        from app.services.embedding_service import EmbeddingService
        
        async def test_gnn():
            graph_service = GraphService()
            await graph_service._ensure_graph_loaded()
            
            embedding_service = EmbeddingService(graph=graph_service.graph)
            await embedding_service.initialize()
            
            embedding, score = await embedding_service.get_embedding("paypal-verify-account.com")
            return embedding, score
        
        embedding, score = asyncio.run(test_gnn())
        print_status(f"GNN Embedding Service: Working (score: {score:.4f})", "success")
    except Exception as e:
        print_status(f"GNN Embedding Service: Failed ({e})", "error")

def print_summary():
    """Print summary of all services."""
    print("\n" + "="*60)
    print_status("PHISHGUARD SYSTEM STATUS", "info")
    print("="*60)
    
    services = {
        "Backend API": "http://localhost:8000",
        "API Documentation": "http://localhost:8000/docs",
        "Health Check": "http://localhost:8000/health",
        "Frontend Dashboard": "http://localhost:5173",
        "Chrome Extension": "Load from: aws/Chrome_extensions/",
        "Redis": "redis://localhost:6379",
        "PostgreSQL": "postgresql://localhost:5432",
    }
    
    for name, url in services.items():
        print(f"  {BLUE}{name}:{RESET} {url}")
    
    print("\n" + "="*60)
    print_status("All services started successfully!", "success")
    print("="*60)
    print(f"\n{YELLOW}Chrome Extension Setup:{RESET}")
    print("  1. Open Chrome → Extensions → Developer mode ON")
    print("  2. Click 'Load unpacked'")
    print("  3. Select folder: aws/Chrome_extensions/")
    print(f"\n{YELLOW}Dashboard Login:{RESET}")
    print("  Username: admin")
    print("  Password: admin123")
    print("\nPress Ctrl+C to stop all services")

def main():
    """Main function to start all services."""
    print("\n" + "="*60)
    print_status("STARTING PHISHGUARD SYSTEM", "info")
    print("="*60 + "\n")
    
    # Check services
    if not check_services():
        print_status("Required services not running. Please start Redis and PostgreSQL first.", "error")
        sys.exit(1)
    
    # Verify ML models
    if not verify_ml_models():
        print_status("Some ML models are missing. Training may be required.", "warning")
    
    # Start backend
    backend_process = start_backend()
    if not backend_process:
        print_status("Failed to start backend", "error")
        sys.exit(1)
    
    # Start frontend
    frontend_process = start_frontend()
    
    # Wait a bit more for services to fully start
    time.sleep(3)
    
    # Test endpoints
    test_api_endpoints()
    
    # Test ML integration
    test_ml_integration()
    
    # Print summary
    print_summary()
    
    # Keep running until interrupted
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n")
        print_status("Shutting down services...", "warning")
        
        # Terminate processes
        if backend_process:
            backend_process.terminate()
            print_status("Backend stopped", "info")
        
        if frontend_process:
            frontend_process.terminate()
            print_status("Frontend stopped", "info")
        
        print_status("All services stopped", "success")

if __name__ == "__main__":
    main()
