@echo off
echo 🔥 Installing TOXINT v3.0.0 - Enhanced OSINT Arsenal
echo ====================================================

python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python 3.8+ is required but not installed.
    echo Please install Python from https://python.org
    pause
    exit /b 1
)

echo ✅ Python detected

echo.
echo 🔧 Setting up virtual environment...
if not exist .venv (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment
        pause
        exit /b 1
    )
    echo ✅ Virtual environment created
) else (
    echo ✅ Virtual environment already exists
)

echo.
echo 📦 Activating virtual environment and installing dependencies...
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo ❌ Failed to activate virtual environment
    pause
    exit /b 1
)

pip install --upgrade pip
pip install -r requirements.txt

if %errorlevel% equ 0 (
    echo ✅ Dependencies installed successfully!
) else (
    echo ❌ Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo 🔧 Setting up configuration...
if not exist config.env (
    if exist config.env.example (
        copy config.env.example config.env >nul
        echo ✅ Created config.env from template
        echo ⚠️  Edit config.env to add your API keys for enhanced features
    ) else (
        echo # TOXINT Configuration > config.env
        echo # Add your API keys below for enhanced functionality >> config.env
        echo HIBP_API_KEY=your-hibp-key-here >> config.env
        echo SHODAN_API_KEY=your-shodan-key-here >> config.env
        echo VIRUSTOTAL_API_KEY=your-virustotal-key >> config.env
        echo ✅ Created basic config.env template
    )
) else (
    echo ✅ config.env already exists
)

echo.
echo 🎯 TOXINT v3.0.0 Installation Complete!
echo ======================================
echo.
echo 🚀 Quick Start:
echo   1. Activate virtual environment: .venv\Scripts\activate.bat
echo   2. Run TOXINT: python toxint.py
echo.
echo 💡 Or use our quick startup script:
echo   start_toxint.bat  (coming soon)
echo.
echo 🔥 Enhanced Modules (New in v3.0.0):
echo   Select module 14 - Hash Reversal Engine
echo   Select module 15 - Smart Auto-Profiler (9 report types!)
echo.
echo 📊 Smart Auto-Profiler Features:
echo   - Intelligent comprehensive target analysis
echo   - 9 advanced report types (Executive, Technical, Timeline, etc.)
echo   - Multi-data correlation and risk assessment
echo   - Self-contained architecture (no module dependencies)
echo.
echo ⚙️  Configuration:
echo   - Edit config.env to add API keys for enhanced features
echo   - Many features work without API keys (100%% free!)
echo   - Configuration status shown in TOXINT banner
echo.
echo 🔗 API Keys (Optional but Recommended):
echo   - HaveIBeenPwned: Email breach checking
echo   - Shodan: Network intelligence
echo   - VirusTotal: Threat intelligence
echo   - OpenCage/Google: Enhanced geolocation
echo.
echo 🔥 Ready to hunt threats with enhanced OSINT capabilities!
echo.
echo ⚠️  Remember to activate virtual environment before use:
echo   .venv\Scripts\activate.bat
echo.
pause
