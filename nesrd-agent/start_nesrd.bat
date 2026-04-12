@echo off
echo Starting NESRD Agent with Watchdog...
cd C:\Users\USER\nesrd-agent
call venv\Scripts\activate.bat
python watchdog.py