@echo off
chcp 65001 >nul
echo ============================================
echo    Security Toolkit 启动脚本
echo ============================================
echo.

cd /d "%~dp0"

if not exist "venv" (
    echo 创建虚拟环境...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo 检查依赖...
pip install -r requirements.txt -q

echo 启动程序...
python main.py

pause
