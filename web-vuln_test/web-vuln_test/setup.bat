@echo off
echo ========================================
echo CODEXIO Vulnerability Scanner Setup
echo ========================================
echo.

echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Python found
    set PYTHON_CMD=python
) else (
    python3 --version >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] Python3 found
        set PYTHON_CMD=python3
    ) else (
        py --version >nul 2>&1
        if %errorlevel% equ 0 (
            echo [OK] Python (py) found
            set PYTHON_CMD=py
        ) else (
            echo [ERROR] Python not found!
            echo Please install Python from https://python.org
            echo Make sure to check "Add Python to PATH" during installation
            pause
            exit /b 1
        )
    )
)

echo.
echo Installing Python dependencies...
%PYTHON_CMD% -m pip install --upgrade pip
%PYTHON_CMD% -m pip install -r Backend/requirements.txt

if %errorlevel% equ 0 (
    echo [OK] Dependencies installed successfully
) else (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo ========================================
echo Setup completed successfully!
echo ========================================
echo.
echo To use the scanner:
echo 1. Start your XAMPP server
echo 2. Open http://localhost/web-vuln_test in your browser
echo 3. Enter a target URL and click Scan
echo.
echo Note: You need a Google Gemini API key for AI analysis
echo Set it in Backend/codexiovuln.py or as environment variable
echo.
pause
