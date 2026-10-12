# MAS-CSI Installation & Deployment Guide

## Quick Setup Instructions

### 1. Download & Extract Repository
You can click **"Download ZIP"** directly in the top navigation bar of the MAS-CSI web interface, or extract the provided archive:
```bash
unzip MAS-CSI-v9-FULL.zip
cd MAS-CSI-v9-FULL
```

### 2. Automated Launch (Windows)
Run the master startup script:
```bat
scripts\run_all_windows.bat
```
This launches:
1. Python FastAPI Backend on `http://localhost:8000`
2. Real Lab WebApp on `http://localhost:5000`
3. React SOC Frontend on `http://localhost:3000`

### 3. Manual Launch (Linux / macOS / WSL)
**Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Lab WebApp:**
```bash
cd lab_webapp
pip install -r requirements.txt
python app.py
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### 4. Running Backend Tests
```bash
cd backend
pytest -v
```
