@echo off
echo ===================================================
echo MAS-CSI Cyber Intelligence Platform Setup
echo ===================================================
echo [1/3] Installing Python Backend dependencies...
cd backend
pip install -r requirements.txt
echo [2/3] Installing Lab WebApp dependencies...
cd ..\lab_webapp
pip install -r requirements.txt
echo [3/3] Installing Frontend dependencies...
cd ..
npm install
echo Setup complete! Run scripts\run_all_windows.bat to launch.
pause
