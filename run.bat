@echo off
setlocal
title Shodan IP Collector

echo ========================================================================
echo                      Shodan IP Collector Launcher
echo ========================================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] ERROR: Python is not installed or not added to your system PATH.
    echo Please download and install Python 3.8+ from https://www.python.org/
    echo Make sure to check the box "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

:: Ensure required Python packages are installed
echo [*] Checking and verifying dependencies...
python -m pip install -r "%~dp0requirements.txt" --quiet
if errorlevel 1 (
    echo [!] Warning: Pip had an issue installing dependencies. Attempting to continue...
)

echo [*] Starting Shodan Collector...
echo.

:: Run the scraper with any passed arguments
python "%~dp0shodan_scraper.py" %*

echo.
echo ========================================================================
echo Script execution completed.
pause
