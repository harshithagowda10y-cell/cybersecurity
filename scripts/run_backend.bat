@echo off
echo Starting MAS-CSI Python FastAPI Backend on port 8000...
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
