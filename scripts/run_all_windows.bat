@echo off
echo =======================================================
echo Launching Full MAS-CSI Cybersecurity Intelligence System
echo =======================================================
start "MAS-CSI Backend (FastAPI)" cmd /k scripts\run_backend.bat
start "MAS-CSI Real Lab WebApp" cmd /k scripts\run_lab_webapp.bat
start "MAS-CSI SOC Frontend" cmd /k scripts\run_frontend.bat
echo All 3 MAS-CSI microservices launched in separate terminals!
