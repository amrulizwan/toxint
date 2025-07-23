#!/bin/bash

echo "🔥 Installing TOXINT v3.0.0 - Enhanced OSINT Arsenal"
echo "===================================================="

# Check Python 3.8+
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3.8+ is required but not installed."
    echo "Please install Python 3.8 or higher from https://python.org"
    exit 1
fi

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then 
    echo "✅ Python $python_version detected"
else
    echo "❌ Python 3.8+ required, found $python_version"
    exit 1
fi

echo ""
echo "� Setting up virtual environment..."
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create virtual environment"
        exit 1
    fi
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

echo ""
echo "📦 Activating virtual environment and installing dependencies..."
source .venv/bin/activate

if [ $? -ne 0 ]; then
    echo "❌ Failed to activate virtual environment"
    exit 1
fi

pip install --upgrade pip
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully!"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""
echo "🔧 Setting up configuration..."
if [ ! -f "config.env" ]; then
    if [ -f "config.env.example" ]; then
        cp config.env.example config.env
        echo "✅ Created config.env from template"
        echo "⚠️  Edit config.env to add your API keys for enhanced features"
    else
        cat > config.env << EOL
# TOXINT Configuration
# Add your API keys below for enhanced functionality
HIBP_API_KEY=your-hibp-key-here
SHODAN_API_KEY=your-shodan-key-here
VIRUSTOTAL_API_KEY=your-virustotal-key
EOL
        echo "✅ Created basic config.env template"
    fi
else
    echo "✅ config.env already exists"
fi

chmod +x toxint.py

echo ""
echo "🎯 TOXINT v3.0.0 Installation Complete!"
echo "======================================"
echo ""
echo "🚀 Quick Start:"
echo "  1. Activate virtual environment: source .venv/bin/activate"
echo "  2. Run TOXINT: python3 toxint.py"
echo ""
echo "💡 Or use our quick commands:"
echo "  source .venv/bin/activate && python3 toxint.py"
echo ""
echo "🔥 Enhanced Modules (New in v3.0.0):"
echo "  Select module 14 - Hash Reversal Engine"
echo "  Select module 15 - Smart Auto-Profiler (9 report types!)"
echo ""
echo "📊 Smart Auto-Profiler Features:"
echo "  - Intelligent comprehensive target analysis"
echo "  - 9 advanced report types (Executive, Technical, Timeline, etc.)"
echo "  - Multi-data correlation and risk assessment"
echo "  - Self-contained architecture (no module dependencies)"
echo ""
echo "⚙️  Configuration:"
echo "  - Edit config.env to add API keys for enhanced features"
echo "  - Many features work without API keys (100% free!)"
echo "  - Configuration status shown in TOXINT banner"
echo ""
echo "🔗 API Keys (Optional but Recommended):"
echo "  - HaveIBeenPwned: Email breach checking"
echo "  - Shodan: Network intelligence"
echo "  - VirusTotal: Threat intelligence"
echo "  - OpenCage/Google: Enhanced geolocation"
echo ""
echo "🔥 Ready to hunt threats with enhanced OSINT capabilities!"
echo ""
echo "⚠️  Remember to activate virtual environment before use:"
echo "  source .venv/bin/activate"
